import json

from fake import FakeConnector

from panic import vault
import test_cli
from test_cli import PW, _steps, armed, bare, cli, open_vault  # noqa: F401

TOKEN = "xoxp-SECRET-TOKEN"


class FakeSlack(FakeConnector):
    def __init__(self, members, snaps, plan="business", owner="Owner@d.com"):
        super().__init__(provider="slack", steps=_steps())
        self._members, self.snaps, self.snapped, self.released = members, snaps, [], []
        self.plan, self.owner = plan, owner

    def detect_plan(self):
        return self.plan

    def workspace(self):
        return "acme"

    def primary_owner(self):
        return self.owner

    def members(self):
        return self._members

    def users(self):
        return list(self._members)

    def verify_admin(self):
        pass

    def snapshot(self, account):
        self.snapped.append(account.id)
        return self.snaps[account.id.removeprefix("slack:")]

    def release(self, account):
        self.released.append(account.id)
        return "Member reactivated."


def token_file(tmp):
    p = tmp / "token"
    p.write_text(TOKEN + "\n")
    return str(p)


def arm(tmp, sl, *extra):
    return cli("arm", "--slack", "--token-file", token_file(tmp), *extra, connectors={"slack": sl})


def test_arm_protects_the_primary_owner_and_never_prints_the_token(bare, capsys):
    sl = FakeSlack({"owner@d.com": "U0", "a@d.com": "U1"}, {"a@d.com": {"active": ["true"]}})
    assert arm(bare, sl) == 0
    d, out = open_vault(), capsys.readouterr()
    by = {a["id"]: a for a in d["accounts"]}
    assert by["slack:owner@d.com"]["protected"] and not by["slack:a@d.com"]["protected"]
    assert by["slack:owner@d.com"]["provider"] == "slack" and "slack:owner@d.com" not in d["baselines"]
    assert d["baselines"]["slack:a@d.com"] == {"active": ["true"]} and sl.snapped == ["slack:a@d.com"]
    assert TOKEN not in out.out + out.err
    assert "business" in out.out and "deactivate" in out.out


def test_arm_stores_the_credentials_and_keeps_existing_baselines(bare):
    sl = FakeSlack({"Owner@d.com": "U0", "A@d.com": "U1"}, {"a@d.com": {"active": ["true"]}})
    arm(bare, sl)
    assert open_vault()["credentials"]["slack"] == {
        "token": TOKEN, "plan": "business", "team": "acme", "users": {"owner@d.com": "U0", "a@d.com": "U1"},
        "primary_owner": "owner@d.com"}
    sl.snaps["a@d.com"] = {"active": ["false"]}
    arm(bare, sl)
    assert open_vault()["baselines"]["slack:a@d.com"] == {"active": ["true"]} and sl.snapped == ["slack:a@d.com"]


def test_arm_fails_clearly_when_the_plan_cannot_be_detected(bare, capsys):
    sl = FakeSlack({}, {})

    def boom():
        raise ConnectionError("network down")
    sl.detect_plan = boom
    assert arm(bare, sl) == 1
    err = capsys.readouterr().err
    assert "plan" in err and "network down" in err and not test_cli.vpath.exists()


def test_arm_needs_a_token_file(bare, capsys):
    assert cli("arm", "--slack", connectors={"slack": FakeSlack({}, {})}) == 1
    assert "--token-file" in capsys.readouterr().err


def test_release_reactivates(armed, capsys):
    d = open_vault()
    d["accounts"].append({"id": "slack:a@d.com", "provider": "slack", "protected": False})
    vault.save(test_cli.vpath, d, PW, test_cli.kpath.read_bytes())
    sl = FakeSlack({}, {})
    assert cli("release", "--user", "slack:a@d.com", answers=["y"], connectors={"slack": sl}) == 0
    assert sl.released == ["slack:a@d.com"] and "Member reactivated." in capsys.readouterr().out
    assert "slack:a@d.com" in open_vault()["released"]


def test_slack_arms_beside_workspace_on_the_same_addresses(bare, capsys):
    from panic.guard import guard_once, new_state
    from panic.model import Account, Finding, Severity
    from test_cli import FakeWorkspace
    key = bare / "sa.json"
    key.write_text(json.dumps({"private_key": "x"}))
    ws = FakeWorkspace(["owner@d.com", "a@d.com"], {"a@d.com": {}})
    assert cli("arm", "--workspace", "--sa-key", str(key), "--admin", "owner@d.com", "--domain", "d.com",
               connectors={"google_workspace": ws}) == 0
    assert arm(bare, FakeSlack({"owner@d.com": "U0", "a@d.com": "U1"}, {"a@d.com": {"active": ["true"]}})) == 0
    d = open_vault()
    by = {x["id"]: x for x in d["accounts"]}
    assert by["a@d.com"]["provider"] == "google_workspace" and by["slack:a@d.com"]["provider"] == "slack"
    assert by["owner@d.com"]["protected"] and by["slack:owner@d.com"]["protected"]
    assert "another provider" not in capsys.readouterr().err
    accounts = [Account(**x) for x in d["accounts"]]
    acts = []
    hit = FakeConnector()
    hit.findings = [Finding("a@d.com", "rule_hides_mail", Severity.TRIGGER, "x")]
    conns = {x.id: hit if x.id == "a@d.com" else FakeConnector() for x in accounts}
    guard_once(accounts, [("a@d.com", "slack:a@d.com")], conns, d["baselines"], set(), new_state(), "press",
               lambda t, f: acts.append(t), lambda f, extra: None, lambda: None, lambda: 1e6)
    assert acts == [["a@d.com", "slack:a@d.com"]]


def test_rehearse_shows_a_slack_member_as_an_organisation_account(armed, capsys):
    d = open_vault()
    d["accounts"].append({"id": "slack:a@d.com", "provider": "slack", "protected": False})
    d["baselines"]["slack:a@d.com"] = {"active": ["true"]}
    vault.save(test_cli.vpath, d, PW, test_cli.kpath.read_bytes())
    sl = FakeSlack({}, {"a@d.com": {"active": ["false"]}})
    cli("rehearse", answers=["n"], connectors={"slack": sl})
    assert "slack:a@d.com: changed since baseline: active" in capsys.readouterr().out
