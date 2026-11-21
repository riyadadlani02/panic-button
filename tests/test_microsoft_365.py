import json

import pytest

from panic.http import ApiError
from panic.microsoft_365 import Microsoft365
from panic.model import Account, Phase, Severity, Step, Tier, WatchPolicy
from test_graph_mail import INBOX, FakeApi, canon, rule, to

ADMIN = "breakglass@corp.test"
A = "a@corp.test"
CRED = {"tenant": "t", "client_id": "c", "client_secret": "SECRET-VALUE", "admin": ADMIN, "domains": ["corp.test"]}
GRANTS = f"/users/{A}/oauth2PermissionGrants"


def conn(api=None):
    return Microsoft365(CRED, api=api or FakeApi(), token=lambda: "tok")


def step(action, account=A):
    return Step(account, action, Phase.FREEZE, Tier.API, "t")


def test_catalog_shape():
    cat = {s.action: s for s in conn().catalog(Account(A, "microsoft_365"))}
    assert list(cat) == ["disable", "sign_out", "inbox_rules", "consent_grants", "mailbox_forwarding", "delegates",
                         "password"]
    assert cat["disable"].phase is Phase.FREEZE and cat["disable"].watch is WatchPolicy.REAPPLY
    assert cat["sign_out"].lingers_s == 3600 and cat["sign_out"].watch is WatchPolicy.NONE
    assert cat["inbox_rules"].after_read and cat["consent_grants"].lingers_s == 3600
    assert all(cat[k].tier is Tier.GUIDED and cat[k].link for k in ("mailbox_forwarding", "delegates", "password"))
    assert "cannot read" in cat["mailbox_forwarding"].title and "cannot read" in cat["delegates"].title


def test_disable_and_readback():
    api = FakeApi({f"/users/{A}": {"accountEnabled": True}})
    c = conn(api)
    assert c.check(step("disable"), {}) is False
    c.run(step("disable"), {})
    assert api.sent == [("PATCH", f"/users/{A}", {"accountEnabled": False})] and c.check(step("disable"), {}) is True


def test_sign_out_has_no_readback():
    api = FakeApi()
    c = conn(api)
    c.run(step("sign_out"), {})
    assert api.sent == [("POST", f"/users/{A}/revokeSignInSessions", None)] and c.check(step("sign_out"), {}) is None


def grant(i, scope, client="app", kind="Principal", principal="uid-a"):
    return {"id": i, "clientId": client, "scope": scope, "consentType": kind, "principalId": principal}


def with_user(data):
    return {f"/users/{A}": {"id": "uid-a"}, **data}


def test_consent_grants_deletion_keeps_baseline():
    keep, bad = grant("1", "User.Read", "ok"), grant("2", "Mail.Read", "evil")
    api = FakeApi(with_user({GRANTS: {"value": [keep, bad]}}))
    c = conn(api)
    base = {"consent_grants": [json.dumps({"clientId": "ok", "scope": "User.Read"}, sort_keys=True)]}
    assert c.check(step("consent_grants"), base) is False
    c.run(step("consent_grants"), base)
    assert api.deleted == ["/oauth2PermissionGrants/2"] and c.check(step("consent_grants"), base) is True


def test_inbox_rules_step_deletes_outside_baseline():
    keep, bad = rule("1", "keep"), rule("2", "bad")
    api = FakeApi({INBOX: {"value": [keep, bad]}})
    c = conn(api)
    c.run(step("inbox_rules"), {"inbox_rules": [canon(keep)]})
    assert api.deleted == [f"{INBOX}/2"]


def test_read_only_rule_fails_the_step():
    api = FakeApi({INBOX: {"value": [rule("2")]}})
    api.stuck = {"2"}
    with pytest.raises(RuntimeError):
        conn(api).run(step("inbox_rules"), {"inbox_rules": []})


@pytest.mark.parametrize("action,path", [("inbox_rules", INBOX), ("consent_grants", GRANTS)])
def test_missing_baseline_category_fails_closed(action, path):
    api = FakeApi(with_user({path: {"value": [rule("1")]}}))
    for call in (lambda c: c.run(step(action), {}), lambda c: c.check(step(action), {})):
        with pytest.raises(KeyError, match=f"no baseline recorded for {action} on {A}"):
            call(conn(api))
    assert api.deleted == []


def test_exhausted_rate_limit_deletes_nothing():
    api = FakeApi({INBOX: ApiError(429, "")})
    with pytest.raises(ApiError):
        conn(api).run(step("inbox_rules"), {"inbox_rules": []})
    assert api.deleted == []


@pytest.mark.parametrize("who", [ADMIN, ADMIN.upper()])
def test_admin_refused_in_run_release_signals_events(who):
    api, c = FakeApi(), conn()
    for call in (lambda: c.run(step("disable", who), {}), lambda: c.release(Account(who, "microsoft_365")),
                 lambda: c.signals(Account(who, "microsoft_365"), {}, {}),
                 lambda: c.events(Account(who, "microsoft_365"), 0)):
        with pytest.raises(ValueError, match="admin"):
            call()
    assert api.sent == []


def test_release_reenables_and_says_to_reset_the_password():
    api = FakeApi({f"/users/{A}": {"accountEnabled": False}})
    msg = conn(api).release(Account(A, "microsoft_365"))
    assert api.sent == [("PATCH", f"/users/{A}", {"accountEnabled": True})]
    assert msg == "Sign-in restored. Reset the password in the Entra admin centre before telling the user."


def test_snapshot_reads_the_three_categories():
    r = rule("1", "r")
    api = FakeApi({INBOX: {"value": [r]}, GRANTS: {"value": [grant("1", "User.Read", "app")]}, f"/users/{A}": {"id": "uid-a"},
                   f"/users/{A}/authentication/methods": {"value": [
                       {"@odata.type": "#microsoft.graph.phoneAuthenticationMethod", "id": "m1"}]}})
    s = conn(api).snapshot(Account(A, "microsoft_365"))
    assert s == {"inbox_rules": [canon(r)],
                 "consent_grants": [json.dumps({"clientId": "app", "scope": "User.Read"}, sort_keys=True)],
                 "auth_methods": ["#microsoft.graph.phoneAuthenticationMethod:m1"]}


def test_users_and_domains_and_verify_admin():
    nxt = "https://graph.microsoft.com/v1.0/users?$skiptoken=1"
    api = FakeApi({"/users": {"value": [{"userPrincipalName": "a@corp.test"}], "@odata.nextLink": nxt},
                   nxt: {"value": [{"userPrincipalName": "b@corp.test"}]},
                   "/domains": {"value": [{"id": "corp.test", "isVerified": True},
                                          {"id": "x.onmicrosoft.com", "isVerified": False}]},
                   f"/users/{ADMIN}": {"accountEnabled": True}})
    c = conn(api)
    assert c.users() == ["a@corp.test", "b@corp.test"] and c.domains() == ["corp.test"]
    c.verify_admin()
    api.data[f"/users/{ADMIN}"] = {"accountEnabled": False}
    with pytest.raises(ValueError):
        c.verify_admin()


def test_signals_codes():
    acct = Account(A, "microsoft_365")
    fwd = canon(rule(actions={"forwardTo": [to("x@evil.test")]}))
    mail = json.dumps({"clientId": "m", "scope": "Mail.Read"}, sort_keys=True)
    files = json.dumps({"clientId": "f", "scope": "Files.ReadWrite"}, sort_keys=True)
    plain = json.dumps({"clientId": "p", "scope": "User.Read"}, sort_keys=True)
    snap = {"inbox_rules": [fwd], "consent_grants": [mail, files, plain], "auth_methods": ["t:1"]}
    base = {"inbox_rules": [], "consent_grants": [], "auth_methods": []}
    by = {f.code: f for f in conn().signals(acct, snap, base)}
    assert set(by) == {"rule_forwards_outside", "app_consent_added", "auth_method_added", "changed"}
    assert all(by[c].severity is Severity.TRIGGER for c in by if c != "changed")
    assert len(by["app_consent_added"].items) == 2 and by["changed"].items == (f"consent_grants: {plain}",)
    assert conn().signals(acct, {"consent_grants": [plain]}, {"consent_grants": []})[0].code == "changed"


def test_events_one_finding_for_the_high_detection():
    path = "/identityProtection/riskDetections"
    api = FakeApi({path: {"value": [{"riskLevel": "high", "riskEventType": "anonymizedIPAddress"},
                                    {"riskLevel": "medium", "riskEventType": "unfamiliarFeatures"}]}})
    out = conn(api).events(Account(A, "microsoft_365"), 0)
    assert [f.code for f in out] == ["provider_flagged_login"] and out[0].severity is Severity.TRIGGER


def test_events_carry_a_stable_key():
    path = "/identityProtection/riskDetections"
    api = FakeApi({path: {"value": [{"id": "d1", "riskLevel": "high", "riskEventType": "x"},
                                    {"riskLevel": "high", "riskEventType": "y", "detectedDateTime": "t"}]}})
    assert [f.key for f in conn(api).events(Account(A, "microsoft_365"), 0)] == ["d1", "y@t"]


def test_events_forbidden_raises_api_error():
    api = FakeApi({"/identityProtection/riskDetections": ApiError(403, "")})
    with pytest.raises(ApiError):
        conn(api).events(Account(A, "microsoft_365"), 0)


def test_secret_is_not_in_any_exception_message():
    def bad():
        raise RuntimeError("AADSTS7000215: invalid client secret")
    c = Microsoft365(CRED, token=bad)
    with pytest.raises(RuntimeError) as e:
        c._api.get("/users")
    assert "SECRET-VALUE" not in str(e.value)


def test_only_the_users_own_consent_grants_are_read_and_deleted():
    own = grant("1", "Mail.Read", "mine")
    rows = [own, grant("2", "Mail.Read", "other", principal="uid-b"), grant("3", "Mail.Read", "wide", "AllPrincipals", None)]
    api = FakeApi(with_user({GRANTS: {"value": rows}}))
    c = conn(api)
    api.data.update({INBOX: {"value": []}, f"/users/{A}/authentication/methods": {"value": []}})
    snap = c.snapshot(Account(A, "microsoft_365"))
    assert snap["consent_grants"] == [json.dumps({"clientId": "mine", "scope": "Mail.Read"}, sort_keys=True)]
    c.run(step("consent_grants"), {"consent_grants": []})
    assert api.deleted == ["/oauth2PermissionGrants/1"]


def test_malformed_page_makes_check_raise():
    for bad in ({}, None):
        api = FakeApi({INBOX: bad})
        with pytest.raises(ApiError):
            conn(api).check(step("inbox_rules"), {"inbox_rules": []})
