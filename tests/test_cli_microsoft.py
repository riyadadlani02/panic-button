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
