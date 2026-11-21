from unittest.mock import patch

from fake import FakeConnector
from test_cli import armed, bare, cli, open_vault  # noqa: F401

from panic import executor
from panic.guided import Guided
from panic.session import Session  # noqa: F401


def _connectors(fake):
    return {"fake": fake, "guided": Guided()}


def test_arm_guided_saves_account_edge_and_no_baseline(armed, capsys):
    assert cli("arm", "--guided", "amazon", "--id", "me@x.test", answers=["y", "mail"]) == 0
    d = open_vault()
    assert {"id": "amazon:me@x.test", "provider": "guided", "protected": False} in d["accounts"]
    assert ["mail", "amazon:me@x.test"] in d["edges"] and "amazon:me@x.test" not in d["baselines"]
    assert "Guided only: the tool cannot read or watch this account." in capsys.readouterr().out


def test_pressing_the_mail_account_lists_its_guided_downstream(armed):
    cli("arm", "--guided", "amazon", "--id", "me@x.test", answers=["y", "mail"])
    v = open_vault()
    from panic.model import Account
    accounts = [Account(**x) for x in v["accounts"]]
    plan = executor.compile_plan(accounts, [tuple(e) for e in v["edges"]], _connectors(FakeConnector()))
    assert any(s.account == "amazon:me@x.test" and s.title.startswith("Amazon: ") for s in plan)


def test_refuses_a_non_https_link(armed, capsys):
    assert cli("arm", "--guided", "amazon", "--id", "me@x.test", "--link", "password=javascript:alert(1)",
               answers=["y", ""]) == 1
    assert "https://" in capsys.readouterr().err and "amazon:me@x.test" not in str(open_vault()["accounts"])


def test_unknown_key_needs_a_link_and_custom_is_stored(armed):
    assert cli("arm", "--guided", "bank2", "--id", "u", answers=["y", ""]) == 1
    assert cli("arm", "--guided", "bank2", "--id", "u", "--name", "Bank Two",
               "--link", "password=https://b.test/pw", answers=["y", ""]) == 0
    assert open_vault()["credentials"]["guided"]["bank2"]["links"] == {"password": "https://b.test/pw"}
    steps = Guided(open_vault()["credentials"]["guided"]).catalog(
        __import__("panic.model", fromlist=["Account"]).Account("bank2:u", "guided"))
    assert steps[0].title == "Bank Two: change the password"


def test_rehearse_skips_guided_accounts(armed, capsys):
    cli("arm", "--guided", "amazon", "--id", "me@x.test", answers=["y", ""])
    guided = Guided()
    guided.snapshot = lambda a: (_ for _ in ()).throw(AssertionError("must not be read"))
    cli("rehearse", connectors=_connectors(FakeConnector()) | {"guided": guided})
    assert "amazon:me@x.test: guided only, not read" in capsys.readouterr().out


def test_real_press_and_dry_run_cover_guided_accounts(armed, capsys):
    from test_cli import latest_report, patch_watch  # noqa: F401
    cli("arm", "--guided", "amazon", "--id", "me@x.test", answers=["y", "mail"])
    conns = _connectors(FakeConnector())
    assert cli("press", "--all", "--dry-run", connectors=conns) == 0
    assert "amazon:me@x.test" in capsys.readouterr().out
    with patch("panic.executor.watch"):
        cli("press", "--user", "mail", "--user", "amazon:me@x.test", connectors=conns, answers=["n"] * 20)
    o = open_vault()["outcomes"][-1]
    g = [r for r in o["results"] if r["step"]["tier"] == "guided"]
    assert g and all(r["status"] == "needs_you" for r in g)
    text = latest_report().read_text()
    assert "## Needs you" in text and "Amazon: " in text.split("## Needs you")[1]
