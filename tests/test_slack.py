import pytest

from panic.http import ApiError
from panic.model import Account, Phase, Severity, Step, Tier, WatchPolicy
from panic.slack import Slack

OWNER = "Owner@corp.test"
A = "a@corp.test"


class FakeApi:
    """Routes map a path to a response, a list of responses (one per call), an exception, or a callable of params."""

    def __init__(self, routes=None):
        self.routes, self.calls, self.sent = routes or {}, [], []

    def _answer(self, path, params):
        r = self.routes.get(path, ApiError(404, "", "no route " + path))
        if isinstance(r, list):
            r = r.pop(0)
        r = r(params) if callable(r) else r
        if isinstance(r, Exception):
            raise r
        return r

    def get(self, path, params=None):
        self.calls.append((path, params))
        return self._answer(path, params)

    def send(self, method, path, body=None):
        self.sent.append((method, path, body))
        return self.routes.get(path + "#" + method, {"ok": True})


def cred(plan="business", **kw):
    return {"token": "xoxp-SECRET", "plan": plan, "team": "acme", "users": {A: "U1", OWNER.lower(): "U0"},
            "primary_owner": OWNER.lower(), **kw}


def conn(plan="business", web=None, scim=None, audit=None, **kw):
    return Slack(cred(plan, **kw), FakeApi() if web is None else web, FakeApi() if scim is None else scim,
                 FakeApi() if audit is None else audit)


def step(action, account=A):
    return Step(account, action, Phase.FREEZE, Tier.API, "t")


def err(name):
    return {"ok": False, "error": name}


# -- plan detection -------------------------------------------------------

def detect(audit=None, scim=None, web=None):
    return conn(web=FakeApi(web), scim=FakeApi(scim), audit=FakeApi(audit)).detect_plan()


NO = ApiError(403, "", "no")
ENT, BIZ, PRO = {"/logs": {"entries": []}}, {"/Users": {"Resources": []}}, {"/team.accessLogs": {"ok": True, "logins": []}}


def test_detects_each_plan():
    assert detect(audit=ENT) == "enterprise"
    assert detect(audit={"/logs": NO}, scim=BIZ) == "business"
    assert detect(audit={"/logs": ApiError(404, "")}, scim={"/Users": NO}, web=PRO) == "pro"
    assert detect(audit={"/logs": NO}, scim={"/Users": NO}, web={"/team.accessLogs": err("paid_only")}) == "free"


@pytest.mark.parametrize("name", ["not_allowed_token_type", "missing_scope", "feature_not_enabled"])
def test_web_api_no_answers_move_detection_down(name):
    assert detect(audit={"/logs": NO}, scim={"/Users": NO}, web={"/team.accessLogs": err(name)}) == "free"


@pytest.mark.parametrize("bad", [ApiError(500, "", "boom"), ApiError(429, "", "slow"), ConnectionError("down"),
                                 ApiError(200, "x", "response was not JSON")])
def test_a_failed_probe_is_not_a_lower_plan(bad):
    with pytest.raises(Exception):
        detect(audit={"/logs": bad})
    with pytest.raises(Exception):
        detect(audit={"/logs": NO}, scim={"/Users": bad})


def test_ratelimited_or_odd_web_error_during_detection_raises():
    for name in ("ratelimited", "internal_error"):
        with pytest.raises(ApiError):
            detect(audit={"/logs": NO}, scim={"/Users": NO}, web={"/team.accessLogs": err(name)})


# -- catalogue ------------------------------------------------------------

def cat(plan):
    return {s.action: s for s in conn(plan).catalog(Account(A, "slack"))}


def test_catalog_per_plan():
    ent, biz, pro, free = cat("enterprise"), cat("business"), cat("pro"), cat("free")
    assert list(ent) == ["reset_sessions", "deactivate", "apps"] and list(biz) == ["deactivate", "apps"]
    assert ent["reset_sessions"].tier is Tier.API and ent["reset_sessions"].phase is Phase.FREEZE
    assert ent["deactivate"].tier is Tier.API and ent["deactivate"].watch is WatchPolicy.REAPPLY
    assert biz["deactivate"].tier is Tier.API
    for c in (ent, biz, pro, free):
        assert c["apps"].tier is Tier.GUIDED and c["apps"].link == "https://acme.slack.com/apps/manage"
    for c in (pro, free):
        assert list(c) == ["deactivate", "apps"]
        assert c["deactivate"].tier is Tier.GUIDED and c["deactivate"].phase is Phase.FREEZE
        assert c["deactivate"].link == "https://acme.slack.com/admin"


# -- reads ----------------------------------------------------------------

def user(i, email, **kw):
    return {"id": i, "profile": {"email": email}, **kw}


def test_members_pages_and_skips_bots_and_deactivated():
    pages = [{"ok": True, "members": [user("U1", "A@corp.test"), user("U2", "b@corp.test", is_bot=True)],
              "response_metadata": {"next_cursor": "c2"}},
             {"ok": True, "members": [user("U3", "c@corp.test", deleted=True), user("USLACKBOT", "s@corp.test"),
                                      user("U4", "d@corp.test", is_primary_owner=True)],
              "response_metadata": {"next_cursor": ""}}]
    web = FakeApi({"/users.list": pages})
    assert conn(web=web).members() == {"a@corp.test": "U1", "d@corp.test": "U4"}
    assert web.calls[1][1]["cursor"] == "c2"


def test_primary_owner():
    web = FakeApi({"/users.list": {"ok": True, "members": [user("U1", "a@corp.test"),
                                                           user("U4", "Boss@corp.test", is_primary_owner=True)]}})
    assert conn(web=web).primary_owner() == "boss@corp.test"


@pytest.mark.parametrize("bad", [{"ok": True}, {"ok": True, "members": "x"}, [[]], None, {"ok": True, "members": [],
                                 "response_metadata": {"next_cursor": 5}}])
def test_a_malformed_list_raises_instead_of_reading_empty(bad):
    with pytest.raises(ApiError):
        conn(web=FakeApi({"/users.list": bad})).members()


def test_a_looping_cursor_raises():
    page = {"ok": True, "members": [], "response_metadata": {"next_cursor": "same"}}
    with pytest.raises(ApiError):
        conn(web=FakeApi({"/users.list": page})).members()


def test_ok_false_on_a_read_raises_with_the_error_name():
    with pytest.raises(ApiError) as e:
        conn(web=FakeApi({"/users.list": err("ratelimited")})).members()
    assert e.value.status == 200 and e.value.body == "ratelimited"


def test_workspace_comes_from_auth_test():
    assert conn(web=FakeApi({"/auth.test": {"ok": True, "url": "https://acme.slack.com/"}})).workspace() == "acme"
    with pytest.raises(ApiError):
        conn(web=FakeApi({"/auth.test": {"ok": True, "url": "https://evil.example/"}})).workspace()


def test_snapshot_reads_active_on_paid_plans_only():
    scim = FakeApi({"/Users/U1": {"active": True}})
    assert conn("business", scim=scim).snapshot(Account(A, "slack")) == {"active": ["true"]}
    scim = FakeApi({"/Users/U1": {"active": False}})
    assert conn("enterprise", scim=scim).snapshot(Account(A, "slack")) == {"active": ["false"]}
    for plan in ("pro", "free"):
        assert conn(plan, scim=FakeApi()).snapshot(Account(A, "slack")) == {}
    with pytest.raises(ApiError):
        conn("business", scim=FakeApi({"/Users/U1": {"userName": "a"}})).snapshot(Account(A, "slack"))


# -- writes ---------------------------------------------------------------

def test_deactivate_and_readback():
    scim = FakeApi({"/Users/U1": {"active": True}})
    c = conn("business", scim=scim)
    assert c.check(step("deactivate"), {}) is False
    c.run(step("deactivate"), {})
    assert scim.sent == [("PATCH", "/Users/U1", {"active": False})]
    scim.routes["/Users/U1"] = {"active": False}
    assert c.check(step("deactivate"), {}) is True


def test_reset_sessions_posts_to_the_admin_method_and_has_no_readback():
    web = FakeApi()
    c = conn("enterprise", web=web)
    c.run(step("reset_sessions"), {})
    assert web.sent == [("POST", "/admin.users.session.reset", {"user_id": "U1"})]
    assert c.check(step("reset_sessions"), {}) is None


def test_a_rejected_web_write_raises():
    web = FakeApi({"/admin.users.session.reset#POST": err("ratelimited")})
    with pytest.raises(ApiError):
        conn("enterprise", web=web).run(step("reset_sessions"), {})


def test_ratelimited_read_makes_run_raise_without_a_scim_write():
    scim = FakeApi()
    web = FakeApi({"/users.list": err("ratelimited")})
    c = conn("business", web=web, scim=scim, users={})  # id unknown, so it has to read the member list
    with pytest.raises(ApiError):
        c.run(step("deactivate"), {})
    assert scim.sent == []


def test_a_member_who_joined_after_arming_is_found():
    web = FakeApi({"/users.list": {"ok": True, "members": [user("U9", "new@corp.test")]}})
    scim = FakeApi()
    conn("business", web=web, scim=scim).run(step("deactivate", "New@corp.test"), {})
    assert scim.sent == [("PATCH", "/Users/U9", {"active": False})]


@pytest.mark.parametrize("who", [OWNER, OWNER.lower(), OWNER.upper()])
def test_primary_owner_is_refused_whatever_the_case(who):
    scim, web = FakeApi(), FakeApi()
    c = conn("enterprise", web=web, scim=scim)
    for act in ("deactivate", "reset_sessions"):
        with pytest.raises(ValueError):
            c.run(step(act, who), {})
    with pytest.raises(ValueError):
        c.release(Account(who, "slack"))
    with pytest.raises(ValueError):
        c.events(Account(who, "slack"), 0)
    assert scim.sent == web.sent == []


def test_release_reactivates_on_paid_plans():
    scim = FakeApi()
    assert conn("business", scim=scim).release(Account(A, "slack")) == "Member reactivated."
    assert scim.sent == [("PATCH", "/Users/U1", {"active": True})]


@pytest.mark.parametrize("plan", ["pro", "free"])
def test_release_refuses_on_plans_without_scim(plan):
    scim = FakeApi()
    with pytest.raises(ValueError, match="acme.slack.com/admin"):
        conn(plan, scim=scim).release(Account(A, "slack"))
    assert scim.sent == []


def test_unknown_action_raises():
    with pytest.raises(ValueError):
        conn().run(step("apps"), {})


def test_the_token_never_appears_in_an_error():
    with pytest.raises(ApiError) as e:
        conn(web=FakeApi({"/users.list": err("ratelimited")})).members()
    assert "SECRET" not in str(e.value) + e.value.body


# -- events ---------------------------------------------------------------

def entry(action, actor=None, entity=None):
    out = {"action": action}
    if actor:
        out["actor"] = {"type": "user", "user": {"id": actor}}
    if entity:
        out["entity"] = {"type": "user", "user": {"id": entity}}
    return out


def test_enterprise_events_match_only_this_member_and_use_since():
    seen = []

    def logs(params):
        seen.append(params)
        return {"entries": [entry("anomaly", actor="U1"), entry("user_logout_compromised", entity="U1"),
                            entry("anomaly", actor="U2"), entry("anomaly", entity="U2")]}
    c = conn("enterprise", audit=FakeApi({"/logs": logs}))
    out = c.events(Account(A, "slack"), 1700000000.5)
    assert len(out) == 1 and out[0].code == "provider_flagged_login" and out[0].severity is Severity.TRIGGER
    assert out[0].items == ("anomaly", "user_logout_compromised")
    assert seen[0]["action"] == "anomaly,user_logout_compromised" and seen[0]["oldest"] == 1700000000


def test_enterprise_events_with_nothing_for_this_member_are_empty_and_follow_pages():
    pages = [{"entries": [entry("anomaly", actor="U2")], "response_metadata": {"next_cursor": "n"}},
             {"entries": [entry("anomaly", actor="U1")]}]
    out = conn("enterprise", audit=FakeApi({"/logs": pages})).events(Account(A, "slack"), 0)
    assert len(out) == 1
    assert conn("enterprise", audit=FakeApi({"/logs": {"entries": []}})).events(Account(A, "slack"), 0) == []


def test_a_malformed_audit_log_raises():
    with pytest.raises(ApiError):
        conn("enterprise", audit=FakeApi({"/logs": {"ok": True}})).events(Account(A, "slack"), 0)


def login(uid, ip, first):
    return {"user_id": uid, "ip": ip, "date_first": first, "date_last": first + 5}


@pytest.mark.parametrize("plan", ["pro", "business"])
def test_access_log_gives_notices_never_triggers(plan):
    pages = [{"ok": True, "logins": [login("U1", "1.1.1.1", 200), login("U1", "old", 50), login("U2", "9.9.9.9", 300)],
              "paging": {"pages": 2}},
             {"ok": True, "logins": [login("U1", "2.2.2.2", 150), login("U1", "1.1.1.1", 400)], "paging": {"pages": 2}}]
    out = conn(plan, web=FakeApi({"/team.accessLogs": pages})).events(Account(A, "slack"), 100)
    assert [(f.code, f.severity, f.items) for f in out] == [
        ("new_access", Severity.NOTICE, ("1.1.1.1",)), ("new_access", Severity.NOTICE, ("2.2.2.2",))]


def test_a_malformed_access_log_raises():
    for bad in ({"ok": True, "logins": []}, {"ok": True, "paging": {"pages": 1}}, err("ratelimited")):
        with pytest.raises(ApiError):
            conn("pro", web=FakeApi({"/team.accessLogs": bad})).events(Account(A, "slack"), 0)


def test_free_has_no_events_and_makes_no_calls():
    web, audit = FakeApi(), FakeApi()
    assert conn("free", web=web, audit=audit).events(Account(A, "slack"), 0) == []
    assert web.calls == audit.calls == []
