import json

from fake import FakeConnector

from panic import vault
import test_cli
from test_cli import PW, _steps, armed, bare, cli, open_vault  # noqa: F401

SECRET = "SECRET-VALUE-123"


class FakeMicrosoft(FakeConnector):
    def __init__(self, users, snaps):
        super().__init__(provider="microsoft_365", steps=_steps())
        self._users, self.snaps, self.snapped = users, snaps, []
        self.released = []

    def users(self):
        return self._users

    def domains(self):
        return ["d.com"]

    def verify_admin(self):
        pass

    def snapshot(self, account):
        self.snapped.append(account.id)
        return self.snaps[account.id]

    def release(self, account):
        self.released.append(account.id)
        return "Sign-in restored. Reset the password in the Entra admin centre before telling the user."


def secret_file(tmp):
    p = tmp / "secret"
    p.write_text(SECRET + "\n")
    return str(p)


def arm(tmp, ms, *extra):
    return cli("arm", "--microsoft-tenant", "t", "--client-id", "c", "--client-secret-file", secret_file(tmp),
               "--admin", "ADMIN@d.com", *extra, connectors={"microsoft_365": ms})


def test_arm_protects_admin_and_keeps_existing_baselines(bare, capsys):
    ms = FakeMicrosoft(["Admin@d.com", "a@d.com"], {"a@d.com": {"inbox_rules": ["RULE-CONTENT"]}})
    assert arm(bare, ms) == 0
    d, out = open_vault(), capsys.readouterr()
    by = {a["id"]: a for a in d["accounts"]}
    assert by["admin@d.com"]["protected"] and not by["a@d.com"]["protected"]
    assert "admin@d.com" not in d["baselines"] and d["baselines"]["a@d.com"] == {"inbox_rules": ["RULE-CONTENT"]}
    assert "RULE-CONTENT" not in out.out + out.err and SECRET not in out.out + out.err
    ms.snaps["a@d.com"] = {"inbox_rules": ["NEW"]}
    assert arm(bare, ms) == 0
    assert open_vault()["baselines"]["a@d.com"] == {"inbox_rules": ["RULE-CONTENT"]} and ms.snapped == ["a@d.com"]


def test_arm_stores_the_credentials(bare):
    arm(bare, FakeMicrosoft(["a@d.com"], {"a@d.com": {}}))
    assert open_vault()["credentials"]["microsoft_365"] == {
        "tenant": "t", "client_id": "c", "client_secret": SECRET, "admin": "admin@d.com", "domains": ["d.com"]}


def test_release_reenables_and_prints_the_sentence(armed, capsys):
    d = open_vault()
    d["accounts"].append({"id": "a@d.com", "provider": "microsoft_365", "protected": False})
    vault.save(test_cli.vpath, d, PW, test_cli.kpath.read_bytes())
    ms = FakeMicrosoft([], {})
    assert cli("release", "--user", "a@d.com", answers=["y"], connectors={"microsoft_365": ms}) == 0
    assert ms.released == ["a@d.com"] and "Reset the password in the Entra admin centre" in capsys.readouterr().out
    assert "a@d.com" in open_vault()["released"]


def test_rehearse_withholds_rule_contents(armed, capsys):
    d = open_vault()
    d["accounts"].append({"id": "a@d.com", "provider": "microsoft_365", "protected": False})
    d["baselines"]["a@d.com"] = {"inbox_rules": []}
    vault.save(test_cli.vpath, d, PW, test_cli.kpath.read_bytes())
    ms = FakeMicrosoft([], {"a@d.com": {"inbox_rules": ["RULE-CONTENT"]}})
    cli("rehearse", connectors={"microsoft_365": ms}, answers=["n"])
    out = capsys.readouterr().out
    assert "RULE-CONTENT" not in out and "inbox_rules: 1 not in baseline" in out


# -- personal Microsoft account -----------------------------------------

def ms_arm(*extra, answers, token=None, who="Me@Outlook.com", **kw):
    f = FakeConnector(provider="microsoft_personal")
    f.snap = {"inbox_rules": ["R1"]}
    calls = []

    def authorize(client_id, login_hint=None):
        calls.append((client_id, login_hint))
        return token or {"client_id": client_id, "cache": "c1", "username": who}

    rc = cli("arm", "--microsoft-personal", "me@outlook.com", "--client-id", "cid", *extra, answers=answers,
             connectors={"microsoft_personal": f}, ms_authorize=authorize, **kw)
    return rc, calls


def test_personal_arm_stores_the_token_and_the_approved_baseline(bare):
    rc, calls = ms_arm(answers=["y", "y"])
    d = open_vault()
    assert rc == 0 and calls == [("cid", "me@outlook.com")]
    assert d["accounts"] == [{"id": "me@outlook.com", "provider": "microsoft_personal", "protected": False}]
    assert d["credentials"]["microsoft_personal"]["me@outlook.com"]["cache"] == "c1"
    assert d["baselines"]["me@outlook.com"] == {"inbox_rules": ["R1"]}


def test_personal_arm_refuses_a_different_signed_in_address_and_stores_nothing(bare, capsys):
    rc, _ = ms_arm(answers=["y", "y"], who="other@outlook.com")
    assert rc == 1 and "other@outlook.com" in capsys.readouterr().err and not test_cli.vpath.exists()


def test_personal_arm_without_a_recovery_method_signs_nothing_in(bare):
    rc, calls = ms_arm(answers=["n"])
    assert rc == 1 and calls == [] and not test_cli.vpath.exists()


def test_personal_reconnect_replaces_the_token_and_nothing_else(bare):
    ms_arm(answers=["y", "y"])
    before = open_vault()
    rc, _ = ms_arm("--reconnect", answers=[], token={"client_id": "cid", "cache": "c2", "username": "ME@outlook.com"})
    after = open_vault()
    assert rc == 0 and after["credentials"]["microsoft_personal"]["me@outlook.com"]["cache"] == "c2"
    before["credentials"]["microsoft_personal"]["me@outlook.com"] = after["credentials"]["microsoft_personal"]["me@outlook.com"]
    assert {k: v for k, v in after.items() if k not in ("saved_at", "version")} == {k: v for k, v in before.items() if k not in ("saved_at", "version")}


def test_personal_reconnect_of_an_unarmed_account_is_refused(bare):
    ms_arm(answers=["y", "y"])
    rc = cli("arm", "--microsoft-personal", "ghost@outlook.com", "--reconnect", "--client-id", "cid",
             ms_authorize=lambda *a, **k: pytest.fail("signed in"))
    assert rc == 1


def test_a_refreshed_token_is_saved_to_the_vault(bare, monkeypatch):
    from unittest.mock import patch
    from panic import microsoft_personal
    from panic.cli import main
    from test_microsoft_personal import fake_msal, ME

    ms_arm(answers=["y", "y"])
    fake_msal(monkeypatch, {"access_token": "T"}, rotate=True)
    seen = []

    class Api:
        def __init__(self, base, headers):
            self.headers = headers

        def get(self, path, params=None):
            seen.append(self.headers()["Authorization"])
            return {"value": []}

    monkeypatch.setattr(microsoft_personal, "Api", Api)
    d = open_vault()
    d["baselines"]["me@outlook.com"] = {"inbox_rules": []}
    s_key = test_cli.kpath.read_bytes()
    vault.save(test_cli.vpath, d, PW, s_key)
    with patch("getpass.getpass", return_value=PW):
        assert main(["--vault", str(test_cli.vpath), "--keyfile", str(test_cli.kpath), "rehearse"]) == 0
    assert seen == ["Bearer T"]
    assert open_vault()["credentials"]["microsoft_personal"]["me@outlook.com"]["cache"] == "rotated"
