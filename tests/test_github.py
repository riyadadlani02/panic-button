import hashlib
import json

import pytest

from panic.github import REPO_REFRESH_S, GitHub
from panic.http import ApiError
from panic.model import Account, Phase, Severity, Tier, WatchPolicy

ME, ORG = Account("me", "github"), Account("org:acme", "github")


def hook(url, events, **kw):
    fp = hashlib.sha256(url.encode()).hexdigest()[:12]
    from urllib.parse import urlsplit
    u = urlsplit(url)
    return item(url=f"{u.scheme}://{u.hostname}{u.path}", fingerprint=fp, events=sorted(events), **kw)


def item(**kw):
    return json.dumps(kw, sort_keys=True)


class FakeApi:
    """Fake Api: lists by path, every delete recorded."""

    def __init__(self, lists=None, objs=None):
        self.lists, self.objs = lists or {}, objs or {}
        self.reads, self.deleted, self.sent = [], [], []
        self.fail_delete = None

    def pages(self, path, params=None, key=None):
        self.reads.append(path)
        v = self.lists.get(path, [])
        if isinstance(v, Exception):
            raise v
        return v

    def get(self, path, params=None):
        v = self.objs[path]
        if isinstance(v, Exception):
            raise v
        return v

    def delete(self, path, gone_ok=True):
        if path == self.fail_delete:
            raise ApiError(500, "")
        self.deleted.append(path)

    def send(self, method, path, body=None):
        self.sent.append((method, path, body))


def gh(api, now=lambda: 0.0, tokens=None):
    return GitHub({"me": "t", "org:acme": "t"} if tokens is None else tokens, api=lambda _id: api, now=now)


def personal_api():
    return FakeApi({
        "/user/keys": [{"id": 1, "key": "K1", "title": "laptop"}, {"id": 2, "key": "K2", "title": "added"}],
        "/user/ssh_signing_keys": [{"id": 3, "key": "S1", "title": "sign"}],
        "/user/gpg_keys": [{"id": 4, "key_id": "G1", "name": "gpg"}],
        "/user/emails": [{"email": "me@x.test", "primary": True}, {"email": "evil@x.test", "primary": False}],
        "/user/repos": [{"id": 11, "full_name": "me/r", "private": True}],
        "/repos/me/r/keys": [{"id": 5, "key": "D1", "title": "deploy"}, {"id": 6, "key": "D2", "title": "evil"}],
        "/repos/me/r/hooks": [{"id": 7, "config": {"url": "https://h.test/x"}, "events": ["push", "fork"]}],
        "/repos/me/r/collaborators": [{"login": "me"}, {"login": "bob"}],
        "/repos/me/r/invitations": [{"id": 8, "invitee": {"login": "carol"}, "permissions": "write"}],
        "/repos/me/r/actions/runners": [{"id": 21, "name": "build-box"}],
    })


KEY_CATS = ("ssh_keys", "signing_keys", "gpg_keys")
REPO_CATS = ("deploy_keys", "webhooks", "collaborators", "invitations")


def baseline_of(api, conn=None, account=ME):
    return (conn or gh(api)).snapshot(account)


def step(conn, action, account=ME):
    return next(s for s in conn.catalog(account) if s.action == action)


def test_personal_snapshot_shape_and_canonical_items():
    snap = gh(personal_api()).snapshot(ME)
    assert set(snap) == {*KEY_CATS, "emails", "repositories", "public_repositories", *REPO_CATS, "runners"}
    assert snap["repositories"] == ["11: me/r"] and snap["public_repositories"] == []
    assert snap["runners"] == ["11:21: build-box"]
    assert snap["ssh_keys"][0] == item(key="K1", title="laptop")
    assert snap["emails"] == [item(email="me@x.test"), item(email="evil@x.test")]
    assert snap["deploy_keys"][0] == item(key="D1", title="deploy", repo_id=11)
    assert snap["webhooks"] == [hook("https://h.test/x", ["push", "fork"], repo_id=11)]
    assert snap["collaborators"] == [item(login="bob", repo_id=11)]  # the owner is not a collaborator
    assert snap["invitations"] == [item(login="carol", repo_id=11, permissions="write")]
    assert not any('"id"' in i for items in snap.values() for i in items)


def test_org_snapshot_shape():
    api = FakeApi({"/orgs/acme/hooks": [{"id": 1, "config": {"url": "https://h.test"}, "events": ["push"]}],
                   "/orgs/acme/outside_collaborators": [{"login": "bob"}],
                   "/orgs/acme/repos": [{"id": 12, "full_name": "acme/r"}],
                   "/repos/acme/r/keys": [{"id": 2, "key": "D", "title": "t"}],
                   "/orgs/acme/actions/runners": [{"id": 31, "name": "org-box"}]})
    snap = gh(api).snapshot(ORG)
    assert snap == {"org_webhooks": [hook("https://h.test", ["push"])],
                    "outside_collaborators": [item(login="bob")],
                    "deploy_keys": [item(key="D", title="t", repo_id=12)],
                    "repositories": ["12: acme/r"], "public_repositories": [],
                    "runners": ["31: org-box"]}


def test_baseline_key_survives_and_added_key_is_deleted():
    api = personal_api()
    c = gh(api)
    base = baseline_of(api, c)
    api.lists["/user/keys"] = [{"id": 9, "key": "NEW", "title": "x"}, *api.lists["/user/keys"]]  # baseline ones on "page two"
    c.run(step(c, "keys"), base)
    assert api.deleted == ["/user/keys/9"]


def test_primary_email_is_never_deleted_even_outside_the_baseline():
    api = personal_api()
    c = gh(api)
    base = {**baseline_of(api, c), "emails": []}
    c.run(step(c, "emails"), base)
    assert api.sent == [("DELETE", "/user/emails", {"emails": ["evil@x.test"]})] and api.deleted == []


def test_a_failed_list_read_means_no_delete_at_all():
    for bad in ("/user/keys", "/user/ssh_signing_keys", "/user/gpg_keys"):
        api = personal_api()
        c = gh(api)
        base = baseline_of(api, c)
        api.lists["/user/keys"] = [{"id": 9, "key": "NEW", "title": "x"}]
        api.lists[bad] = ApiError(500, "")
        with pytest.raises(ApiError):
            c.run(step(c, "keys"), base)
        assert api.deleted == []


def test_missing_baseline_category_fails_closed():
    api = personal_api()
    c = gh(api)
    base = baseline_of(api, c)
    del base["signing_keys"]
    with pytest.raises(KeyError, match="no baseline recorded for signing_keys on me"):
        c.run(step(c, "keys"), base)
    with pytest.raises(KeyError, match="no baseline recorded for signing_keys on me"):
        c.check(step(c, "keys"), base)
    assert api.deleted == []


def test_repo_categories_are_cached_for_the_hour_by_snapshot_but_not_by_run():
    api, t = personal_api(), [0.0]
    c = gh(api, now=lambda: t[0])
    base = c.snapshot(ME)
    n = api.reads.count("/user/repos")
    c.snapshot(ME)
    assert api.reads.count("/user/repos") == n
    t[0] = REPO_REFRESH_S - 1
    c.snapshot(ME)
    assert api.reads.count("/user/repos") == n
    c.run(step(c, "repo_access"), base)
    assert api.reads.count("/user/repos") == n + 1  # run never trusts the cache
    n = api.reads.count("/user/repos")
    c.snapshot(ME)
    assert api.reads.count("/user/repos") == n  # and its fresh read refreshed it
    t[0] += REPO_REFRESH_S + 1
    c.snapshot(ME)
    assert api.reads.count("/user/repos") == n + 1


def test_repo_access_deletes_in_fixed_order_and_stops_at_the_first_failure():
    api = personal_api()
    c = gh(api)
    base = {**baseline_of(api, c), **{k: [] for k in REPO_CATS}}
    api.fail_delete = "/repos/me/r/keys/6"
    with pytest.raises(ApiError):
        c.run(step(c, "repo_access"), base)
    assert api.deleted == ["/repos/me/r/keys/5"]
    api.fail_delete = None
    c.run(step(c, "repo_access"), base)
    assert api.deleted[1:] == ["/repos/me/r/keys/5", "/repos/me/r/keys/6", "/repos/me/r/hooks/7",
                               "/repos/me/r/collaborators/bob", "/repos/me/r/invitations/8"]


def test_org_access_removes_what_is_outside_the_baseline():
    api = FakeApi({"/orgs/acme/hooks": [{"id": 1, "config": {"url": "https://h.test"}, "events": ["push"]}],
                   "/orgs/acme/outside_collaborators": [{"login": "bob"}]})
    c = gh(api)
    c.run(step(c, "org_access", ORG), {"org_webhooks": [], "outside_collaborators": [], "deploy_keys": [],
                                       "repositories": []})
    assert api.deleted == ["/orgs/acme/hooks/1", "/orgs/acme/outside_collaborators/bob"]


def test_check_is_true_only_when_nothing_is_outside_the_baseline():
    api = personal_api()
    c = gh(api)
    base = baseline_of(api, c)
    assert c.check(step(c, "keys"), base) is True and c.check(step(c, "repo_access"), base) is True
    api.lists["/user/gpg_keys"] = [{"id": 4, "key_id": "G1", "name": "gpg"}, {"id": 9, "key_id": "G2", "name": "n"}]
    assert c.check(step(c, "keys"), base) is False
    assert c.check(step(c, "sign_out"), base) is None


def test_signals_codes():
    api = personal_api()
    c = gh(api)
    base = baseline_of(api, c)
    snap = {**base, "ssh_keys": [*base["ssh_keys"], "x"], "emails": [*base["emails"], "e"],
            "webhooks": [*base["webhooks"], "w"]}
    got = {f.code: f for f in c.signals(ME, snap, base)}
    assert set(got) == {"key_added", "email_added", "repo_access_added"}
    assert all(f.severity is Severity.TRIGGER for f in got.values())
    org = {"org_webhooks": [], "outside_collaborators": [], "deploy_keys": []}
    assert [f.code for f in c.signals(ORG, {**org, "deploy_keys": ["d"]}, org)] == ["org_access_added"]
    with pytest.raises(KeyError):
        c.signals(ME, snap, {k: v for k, v in base.items() if k != "emails"})


def test_catalog_personal_and_org():
    c = gh(FakeApi())
    steps = {s.action: s for s in c.catalog(ME)}
    assert [s.action for s in c.catalog(ME)] == ["keys", "emails", "repo_access", "sign_out", "tokens", "apps",
                                                 "two_factor", "password"]
    assert (steps["keys"].phase, steps["keys"].tier, steps["keys"].watch) == (Phase.FREEZE, Tier.API, WatchPolicy.REAPPLY)
    assert (steps["emails"].phase, steps["repo_access"].phase) == (Phase.PURGE, Phase.PURGE)
    assert steps["sign_out"].phase is Phase.FREEZE and steps["sign_out"].link == "https://github.com/settings/sessions"
    assert steps["password"].link == "https://github.com/settings/security"
    assert "panic arm --github me --token-file FILE --reconnect" in steps["password"].title
    org = {s.action: s for s in c.catalog(ORG)}
    assert list(org) == ["org_access", "members"] and org["members"].link == "https://github.com/orgs/acme/people"
    assert org["members"].tier is Tier.GUIDED


def test_login_and_org_admin():
    api = FakeApi(objs={"/user": {"login": "Me"}, "/user/memberships/orgs/acme": {"state": "active", "role": "admin"}})
    c = gh(api)
    assert c.login("me") == "Me" and c.is_org_admin(ORG) is True
    for m in ({"state": "pending", "role": "admin"}, {"state": "active", "role": "member"}):
        api.objs["/user/memberships/orgs/acme"] = m
        assert c.is_org_admin(ORG) is False
    api.objs["/user/memberships/orgs/acme"] = ApiError(404, "")
    assert c.is_org_admin(ORG) is False


def test_no_token_for_the_account_is_a_key_error():
    with pytest.raises(KeyError, match="no token for account me"):
        gh(FakeApi(), tokens={}).snapshot(ME)


SECRET_HOOK = "https://user:pw@hooks.example.test/x?token=SECRET"


def test_webhook_item_never_holds_the_secret_but_tells_tokens_apart():
    api = personal_api()
    api.lists["/repos/me/r/hooks"] = [{"id": 1, "config": {"url": SECRET_HOOK}, "events": ["push"]},
                                      {"id": 2, "config": {"url": SECRET_HOOK.replace("SECRET", "OTHER")}, "events": ["push"]}]
    a, b = gh(api).snapshot(ME)["webhooks"]
    assert "SECRET" not in a and "pw" not in a and "OTHER" not in b and "user" not in a
    assert json.loads(a)["url"] == "https://hooks.example.test/x" and a != b


def test_baseline_webhook_survives_run_and_same_path_other_token_is_deleted():
    api = personal_api()
    api.lists["/repos/me/r/hooks"] = [{"id": 1, "config": {"url": SECRET_HOOK}, "events": ["push"]}]
    c = gh(api)
    base = c.snapshot(ME)
    api.lists["/repos/me/r/hooks"].append({"id": 2, "config": {"url": SECRET_HOOK.replace("SECRET", "NEW")},
                                           "events": ["push"]})
    c.run(step(c, "repo_access"), base)
    assert api.deleted == ["/repos/me/r/hooks/2"]


def test_a_renamed_repository_is_only_a_changed_notice_and_run_deletes_nothing():
    api = personal_api()
    c = gh(api)
    base = c.snapshot(ME)
    api.lists["/user/repos"] = [{"id": 11, "full_name": "me/renamed"}]
    for path in ("keys", "hooks", "collaborators", "invitations", "actions/runners"):
        api.lists[f"/repos/me/renamed/{path}"] = api.lists.pop(f"/repos/me/r/{path}")
    c.run(step(c, "repo_access"), base)
    assert api.deleted == [] and c.check(step(c, "repo_access"), base) is True
    found = c.signals(ME, gh(api).snapshot(ME), base)  # a new connector: the list of repositories is cached
    assert [(f.code, f.severity, f.items) for f in found] == [("changed", Severity.NOTICE, ("repositories: 11: me/renamed",))]


def test_an_org_repository_rename_deletes_no_deploy_key():
    api = FakeApi({"/orgs/acme/repos": [{"id": 12, "full_name": "acme/r"}],
                   "/repos/acme/r/keys": [{"id": 2, "key": "D", "title": "t"}]})
    c = gh(api)
    base = c.snapshot(ORG)
    api.lists["/orgs/acme/repos"] = [{"id": 12, "full_name": "acme/new"}]
    api.lists["/repos/acme/new/keys"] = api.lists.pop("/repos/acme/r/keys")
    c.run(step(c, "org_access", ORG), base)
    assert api.deleted == [] and [f.code for f in c.signals(ORG, gh(api).snapshot(ORG), base)] == ["changed"]


def test_an_invitation_without_an_invitee_is_still_read():
    api = personal_api()
    api.lists["/repos/me/r/invitations"] = [{"id": 8, "invitee": None, "email": "x@y.test", "permissions": "read"},
                                           {"id": 9, "invitee": None, "permissions": "read"}]
    assert gh(api).snapshot(ME)["invitations"] == [item(email="x@y.test", permissions="read", repo_id=11),
                                                   item(id=9, permissions="read", repo_id=11)]


def test_a_baseline_without_repositories_fails_closed_before_any_delete():
    api = personal_api()
    c = gh(api)
    base = {k: v for k, v in c.snapshot(ME).items() if k != "repositories"}
    base = {**base, **{k: [] for k in REPO_CATS}}
    with pytest.raises(KeyError, match="no baseline recorded for repositories on me"):
        c.run(step(c, "repo_access"), base)
    with pytest.raises(KeyError, match="no baseline recorded for repositories on me"):
        c.check(step(c, "repo_access"), base)
    org = {"org_webhooks": [], "outside_collaborators": [], "deploy_keys": []}
    with pytest.raises(KeyError, match="repositories"):
        c.run(step(c, "org_access", ORG), org)
    assert api.deleted == []


def test_a_public_repository_created_or_made_public_is_risky_and_a_private_one_is_not():
    api = personal_api()
    base = gh(api).snapshot(ME)
    api.lists["/user/repos"] = [*api.lists["/user/repos"], {"id": 12, "full_name": "me/new", "private": True}]
    assert [(f.code, f.severity) for f in gh(api).signals(ME, gh(api).snapshot(ME), base)] == [
        ("changed", Severity.NOTICE)]
    api.lists["/user/repos"] = [*api.lists["/user/repos"], {"id": 13, "full_name": "me/open", "private": False}]
    got = {f.code: f for f in gh(api).signals(ME, gh(api).snapshot(ME), base)}
    assert got["repo_made_public"].severity is Severity.TRIGGER
    assert got["repo_made_public"].items == ("public_repositories: 13: me/open",)
    api.lists["/user/repos"] = [{"id": 11, "full_name": "me/r", "private": False}]  # flipped
    got = {f.code: f for f in gh(api).signals(ME, gh(api).snapshot(ME), base)}
    assert got["repo_made_public"].items == ("public_repositories: 11: me/r",)


def test_a_new_runner_is_risky_on_a_repository_and_an_organisation():
    api = personal_api()
    base = gh(api).snapshot(ME)
    api.lists["/repos/me/r/actions/runners"] = [*api.lists["/repos/me/r/actions/runners"], {"id": 22, "name": "evil"}]
    got = gh(api).signals(ME, gh(api).snapshot(ME), base)
    assert [(f.code, f.severity, f.items) for f in got] == [
        ("runner_added", Severity.TRIGGER, ("runners: 11:22: evil",))]
    org = {"org_webhooks": [], "outside_collaborators": [], "deploy_keys": [], "repositories": [],
           "public_repositories": [], "runners": []}
    assert [f.code for f in gh(api).signals(ORG, {**org, "runners": ["31: x"]}, org)] == ["runner_added"]
    assert [f.code for f in gh(api).signals(ORG, {**org, "public_repositories": ["1: acme/x"]}, org)] == [
        "repo_made_public"]


def test_repo_access_removes_only_runners_outside_the_baseline_and_reads_back():
    api = personal_api()
    c = gh(api)
    base = c.snapshot(ME)
    api.lists["/repos/me/r/actions/runners"] = [{"id": 21, "name": "build-box"}, {"id": 22, "name": "evil"}]
    assert c.check(step(c, "repo_access"), base) is False
    c.run(step(c, "repo_access"), base)
    assert api.deleted == ["/repos/me/r/actions/runners/22"]
    api.lists["/repos/me/r/actions/runners"] = [{"id": 21, "name": "build-box"}]
    assert c.check(step(c, "repo_access"), base) is True


def test_org_access_removes_org_runners_outside_the_baseline():
    api = FakeApi({"/orgs/acme/actions/runners": [{"id": 31, "name": "org-box"}, {"id": 32, "name": "evil"}]})
    c = gh(api)
    c.run(step(c, "org_access", ORG), {"org_webhooks": [], "outside_collaborators": [], "deploy_keys": [],
                                       "repositories": [], "runners": ["31: org-box"]})
    assert api.deleted == ["/orgs/acme/actions/runners/32"]


def test_a_baseline_without_runners_removes_no_runner_but_still_the_rest():
    api = personal_api()
    c = gh(api)
    base = {k: v for k, v in c.snapshot(ME).items() if k not in ("runners", "public_repositories")}
    api.lists["/repos/me/r/actions/runners"].append({"id": 22, "name": "evil"})
    api.lists["/repos/me/r/keys"].append({"id": 9, "key": "D9", "title": "new"})
    c.run(step(c, "repo_access"), base)
    assert api.deleted == ["/repos/me/r/keys/9"]
    api.lists["/repos/me/r/keys"].pop()
    assert c.check(step(c, "repo_access"), base) is True
    api = FakeApi({"/orgs/acme/actions/runners": [{"id": 32, "name": "evil"}]})
    c = gh(api)
    c.run(step(c, "org_access", ORG), {"org_webhooks": [], "outside_collaborators": [], "deploy_keys": [],
                                       "repositories": []})
    assert api.deleted == []


def test_runners_unreadable_without_admin_count_as_none_for_that_repository():
    for status in (403, 404):
        api = personal_api()
        api.lists["/user/repos"].append({"id": 12, "full_name": "me/shared", "private": True})
        api.lists["/repos/me/r/actions/runners"] = ApiError(status, "")
        api.lists["/repos/me/shared/actions/runners"] = [{"id": 23, "name": "box"}]
        assert gh(api).snapshot(ME)["runners"] == ["12:23: box"]
    api = personal_api()
    api.lists["/repos/me/r/actions/runners"] = ApiError(500, "")
    with pytest.raises(ApiError):
        gh(api).snapshot(ME)


@pytest.mark.parametrize("limited", [
    ApiError(403, '{"message": "API rate limit exceeded for user ID 1."}'),
    ApiError(403, '{"message": "You have exceeded a secondary rate limit."}'),
    ApiError(403, "", headers={"x-ratelimit-remaining": "0"}),
    ApiError(403, "", headers={"retry-after": "60"}),
])
def test_a_rate_limited_runners_read_fails_and_caches_nothing(limited):
    api, t = personal_api(), [0.0]
    c = gh(api, now=lambda: t[0])
    good = api.lists["/repos/me/r/actions/runners"]
    api.lists["/repos/me/r/actions/runners"] = limited
    with pytest.raises(ApiError):
        c.snapshot(ME)
    api.lists["/repos/me/r/actions/runners"] = good
    assert c.snapshot(ME)["runners"] == ["11:21: build-box"]  # read again, not an empty list from the cache


def test_a_rate_limited_repository_list_fails_and_caches_nothing():
    api = personal_api()
    c = gh(api)
    good = api.lists["/user/repos"]
    api.lists["/user/repos"] = ApiError(403, '{"message": "API rate limit exceeded"}')
    with pytest.raises(ApiError):
        c.snapshot(ME)
    api.lists["/user/repos"] = good
    assert c.snapshot(ME)["repositories"] == ["11: me/r"]


def test_a_renamed_public_repository_is_a_notice_not_a_trigger():
    api = personal_api()
    api.lists["/user/repos"] = [{"id": 11, "full_name": "me/r", "private": False}]
    base = gh(api).snapshot(ME)
    api.lists["/user/repos"] = [{"id": 11, "full_name": "me/renamed", "private": False}]
    assert [(f.code, f.severity) for f in gh(api).signals(ME, gh(api).snapshot(ME), base)] == [
        ("changed", Severity.NOTICE)]


def test_an_ephemeral_runner_triggers_until_the_scope_already_autoscales():
    api = personal_api()
    c = gh(api)
    base = c.snapshot(ME)
    assert base["runners"] == ["11:21: build-box"]  # unchanged format
    eph = lambda i: {"id": i, "name": "job", "ephemeral": True}
    api.lists["/repos/me/r/actions/runners"] = [{"id": 21, "name": "build-box"}, eph(22)]
    assert "runner_added" in [f.code for f in gh(api).signals(ME, gh(api).snapshot(ME), base)]
    base = gh(api).snapshot(ME)  # "It was me"
    api.lists["/repos/me/r/actions/runners"].append(eph(23))
    assert [(f.code, f.severity) for f in gh(api).signals(ME, gh(api).snapshot(ME), base)] == [
        ("changed", Severity.NOTICE)]
    api.lists["/repos/me/r/actions/runners"].append({"id": 24, "name": "evil"})
    assert "runner_added" in [f.code for f in gh(api).signals(ME, gh(api).snapshot(ME), base)]
    api.lists["/user/repos"].append({"id": 12, "full_name": "me/o", "private": True})  # another repo: no approval
    api.lists["/repos/me/o/actions/runners"] = [eph(30)]
    got = [f for f in gh(api).signals(ME, gh(api).snapshot(ME), base) if f.code == "runner_added"]
    assert any("12:30" in i for i in got[0].items)


def test_an_ephemeral_org_runner_triggers_until_the_org_already_autoscales():
    api = personal_api()
    org = {"org_webhooks": [], "outside_collaborators": [], "deploy_keys": [], "repositories": [],
           "public_repositories": [], "runners": []}
    c = gh(api)
    assert [f.code for f in c.signals(ORG, {**org, "runners": ["ephemeral 31: x"]}, org)] == ["runner_added"]
    base = {**org, "runners": ["ephemeral 31: x"]}
    assert [f.code for f in c.signals(ORG, {**base, "runners": ["ephemeral 31: x", "ephemeral 32: y"]}, base)] == [
        "changed"]
