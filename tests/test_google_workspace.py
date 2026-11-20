import json
from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from googleapiclient.errors import HttpError

from panic import google_workspace
from panic.google_workspace import Workspace
from panic.model import Account, Phase, Step, Tier

ACCT = Account("a@corp.test", "google_workspace")
ADMIN = "breakglass@corp.test"


@pytest.fixture
def sa_info():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    return {"type": "service_account", "client_email": "sa@p.iam.gserviceaccount.com", "private_key": key,
            "token_uri": "https://oauth2.googleapis.com/token", "project_id": "p"}


@pytest.fixture
def directory():
    return MagicMock()


@pytest.fixture
def gmail():
    return MagicMock()


@pytest.fixture
def subjects_used():
    return {}


@pytest.fixture
def sleeps():
    return []


@pytest.fixture
def deleted(gmail):
    # Records the address of every forwarding-address or delegate deletion.
    out = set()
    s = gmail.users().settings()
    s.forwardingAddresses().delete.side_effect = lambda userId, forwardingEmail: out.add(forwardingEmail) or MagicMock()
    s.delegates().delete.side_effect = lambda userId, delegateEmail: out.add(delegateEmail) or MagicMock()
    s.forwardingAddresses().list().execute.return_value = {"forwardingAddresses": [
        {"forwardingEmail": e} for e in ("in@corp.test", "out@evil.test", "new@corp.test")]}
    s.delegates().list().execute.return_value = {"delegates": [{"delegateEmail": "pa@corp.test"}]}
    return out


@pytest.fixture
def conn(sa_info, directory, gmail, subjects_used, sleeps):
    def build(api, version, credentials, **kw):
        subjects_used[api] = credentials._subject
        return directory if api == "admin" else gmail
    return Workspace(sa_info, ADMIN, "corp.test", build=build, sleep=sleeps.append)


def step(action, account="a@corp.test"):
    return Step(account, action, Phase.PURGE, Tier.API, action)


def http_error(status):
    return HttpError(MagicMock(status=status, reason="x"), json.dumps({}).encode())


def test_suspend_and_readback(conn, directory):
    conn.run(step("suspend"), {})
    directory.users().update.assert_called_with(userKey="a@corp.test", body={"suspended": True})
    directory.users().get().execute.return_value = {"suspended": True}
    assert conn.check(step("suspend"), {}) is True


def test_sign_out_has_no_readback_and_lingers(conn):
    s = next(x for x in conn.catalog(ACCT) if x.action == "sign_out")
    assert conn.check(s, {}) is None and s.lingers_s == 3600


def test_outside_domain_forwarding_goes_even_if_baselined(conn, deleted):
    conn.run(step("forwarding_addresses"), {"forwarding_addresses": ["in@corp.test", "out@evil.test"]})
    assert deleted == {"out@evil.test", "new@corp.test"}


def test_forwarding_addresses_without_baseline_still_removes_outsiders_then_raises(conn, deleted):
    with pytest.raises(KeyError, match="no baseline recorded for forwarding_addresses on a@corp.test"):
        conn.run(step("forwarding_addresses"), {})
    assert deleted == {"out@evil.test"}


@pytest.mark.parametrize("action", ["filters", "recovery"])
def test_missing_baseline_is_unknown_not_empty(conn, directory, gmail, action):
    with pytest.raises(KeyError, match=f"no baseline recorded for {action} on a@corp.test"):
        conn.run(step(action), {})
    directory.users().update.assert_not_called()
    gmail.users().settings().filters().delete.assert_not_called()


def test_all_delegates_removed(conn, deleted):
    conn.run(step("delegates"), {"delegates": ["pa@corp.test"]})
    assert deleted == {"pa@corp.test"}


def test_recovery_restored_to_baseline_with_blank_for_unlisted(conn, directory):
    conn.run(step("recovery"), {"recovery": ["email:me@home.test"]})
    directory.users().update.assert_called_with(
        userKey="a@corp.test", body={"recoveryEmail": "me@home.test", "recoveryPhone": ""})


def test_recovery_snapshot_lists_only_non_empty(conn, directory):
    directory.users().get().execute.return_value = {"recoveryEmail": "", "recoveryPhone": "+441"}
    assert conn.snapshot(ACCT)["recovery"] == ["phone:+441"]


def test_gmail_calls_impersonate_the_target_and_directory_calls_the_admin(conn, subjects_used):
    conn.run(step("forwarding_off"), {})
    conn.run(step("suspend"), {})
    assert subjects_used == {"gmail": "a@corp.test", "admin": ADMIN}


def test_rate_limit_is_retried_then_reported(conn, directory, sleeps):
    directory.users().signOut().execute.side_effect = [http_error(429), http_error(503), None]
    conn.run(step("sign_out"), {})
    assert sleeps == [1, 2]
    directory.users().signOut().execute.side_effect = [http_error(429)] * 4
    with pytest.raises(HttpError):
        conn.run(step("sign_out"), {})
    assert sleeps == [1, 2, 1, 2, 4]


def test_other_http_errors_are_not_retried(conn, directory, sleeps):
    directory.users().signOut().execute.side_effect = [http_error(403), None]
    with pytest.raises(HttpError):
        conn.run(step("sign_out"), {})
    assert sleeps == []


def test_running_twice_on_an_already_clean_account_is_quiet(conn, directory):
    directory.tokens().list().execute.return_value = {}
    directory.tokens().delete().execute.side_effect = http_error(404)
    conn.run(step("revoke_apps"), {})
    conn.run(step("revoke_apps"), {})


def test_a_404_on_delete_counts_as_gone(conn, directory):
    directory.tokens().list().execute.return_value = {"items": [{"clientId": "c1"}]}
    directory.tokens().delete().execute.side_effect = http_error(404)
    conn.run(step("revoke_apps"), {})
    directory.tokens().delete.assert_any_call(userKey="a@corp.test", clientId="c1")


def test_release_unsuspends_and_returns_a_temp_password(conn, directory):
    pw = conn.release(ACCT)
    body = directory.users().update.call_args.kwargs["body"]
    assert body["suspended"] is False and body["changePasswordAtNextLogin"] is True
    assert body["password"] == pw and len(pw) >= 16


def test_reset_password_sets_a_forced_change(conn, directory):
    conn.run(step("reset_password"), {})
    body = directory.users().update.call_args.kwargs["body"]
    assert body["changePasswordAtNextLogin"] is True and len(body["password"]) >= 16


def test_refuses_to_act_on_its_own_admin(conn, directory, gmail):
    with pytest.raises(ValueError):
        conn.run(step("suspend", account=ADMIN), {})
    assert directory.mock_calls == [] and gmail.mock_calls == []


def test_users_pages_through_the_tenant(conn, directory):
    directory.users().list().execute.side_effect = [
        {"users": [{"primaryEmail": "a@corp.test"}], "nextPageToken": "t"},
        {"users": [{"primaryEmail": "b@corp.test"}]}]
    assert conn.users() == ["a@corp.test", "b@corp.test"]
    assert directory.users().list.call_args.kwargs == {"domain": "corp.test", "maxResults": 500, "pageToken": "t"}


def test_scopes_cannot_read_mail():
    assert not any(s.endswith(("gmail.readonly", "gmail.modify", "mail.google.com/")) for s in google_workspace.SCOPES)
    assert len(google_workspace.SCOPES) == 4


def test_admin_guard_ignores_case(conn, directory, gmail):
    with pytest.raises(ValueError):
        conn.run(step("suspend", account="BreakGlass@Corp.test"), {})
    assert directory.mock_calls == [] and gmail.mock_calls == []


def test_release_refuses_the_admin(conn, directory, gmail):
    with pytest.raises(ValueError):
        conn.release(Account("Breakglass@corp.test", "google_workspace"))
    assert directory.mock_calls == [] and gmail.mock_calls == []


def test_suspend_readback_treats_absent_field_as_not_suspended(conn, directory):
    directory.users().get().execute.return_value = {}
    assert conn.check(step("suspend"), {}) is False


def test_filter_delete_404_is_quiet_and_429_is_retried(conn, gmail, sleeps):
    s = gmail.users().settings().filters()
    s.list().execute.return_value = {"filter": [{"id": "f1", "criteria": {"from": "x"}, "action": {}}]}
    s.delete().execute.side_effect = [http_error(429), http_error(404)]
    conn.run(step("filters"), {"filters": []})
    assert sleeps == [1]
