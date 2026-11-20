import json
import os
import stat
import time
from dataclasses import replace
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fake import FakeConnector

from panic import executor, log, vault
from panic.cli import main, outcome_from_json, outcome_to_json
from panic.model import Evidence, Outcome, Phase, Result, Status, Step, Tier, WatchPolicy

PW = "pw"
fake = vpath = kpath = report_path = log_path = None


def _steps():
    return [Step("", "freeze", Phase.FREEZE, Tier.API, "Freeze"), Step("", "purge", Phase.PURGE, Tier.API, "Purge")]


@pytest.fixture
def bare(tmp_path):
    """Paths set, no vault yet."""
    global fake, vpath, kpath, report_path, log_path
    fake = FakeConnector(steps=_steps())
    vpath, kpath = tmp_path / "vault" / "panic.vault", tmp_path / "key"
    report_path, log_path = Path(f"{vpath}.report.md"), Path(f"{vpath}.log.jsonl")
    return tmp_path


@pytest.fixture
def armed(bare):
    vpath.parent.mkdir()
    key = vault.new_keyfile()
    kpath.write_bytes(key)
    vault.save(vpath, {
        "accounts": [{"id": "mail", "provider": "fake", "protected": False},
                     {"id": "bank", "provider": "fake", "protected": False},
                     {"id": "boss", "provider": "fake", "protected": True}],
        "edges": [["mail", "bank"]], "baselines": {"mail": {}, "bank": {}}, "credentials": {}, "released": [],
    }, PW, key)


@pytest.fixture
def patch_watch(monkeypatch):
    m = MagicMock()
    monkeypatch.setattr(executor, "watch", m)
    return m


def open_vault():
    return vault.load(vpath, PW, kpath.read_bytes())


def cli(*args, passphrase=PW, answers=(), connectors=None, authorize=None):
    it = iter(answers)

    def fake_input(prompt=""):
        try:
            return next(it)
        except StopIteration:
            raise EOFError

    with patch("getpass.getpass", return_value=passphrase), patch("builtins.input", fake_input):
        return main(["--vault", str(vpath), "--keyfile", str(kpath), *args],
                    connectors={"fake": fake} if connectors is None else connectors, authorize=authorize)


# -- the brief's tests ---------------------------------------------------

def test_dry_run_changes_nothing_and_writes_no_outcome(armed):
    assert cli("press", "--all", "--dry-run") == 0 and fake.ran == [] and "last_outcome" not in open_vault()
    assert not report_path.exists()


def test_press_all_skips_protected_and_writes_report_and_log(armed, patch_watch):
    assert cli("press", "--all") == 0
    assert not any(k.startswith("boss/") for k in fake.ran)
    assert "## Locked" in report_path.read_text() and log.verify(log_path) and patch_watch.called


def test_press_requires_a_target_and_rejects_protected_or_unknown(armed):
    assert cli("press") != 0 and cli("press", "--user", "boss") != 0 and cli("press", "--user", "nobody") != 0
    assert fake.ran == []


def test_wrong_passphrase_is_one_line_not_a_traceback(armed, capsys):
    assert cli("map", passphrase="wrong") == 1 and "Traceback" not in capsys.readouterr().err


def test_rehearse_reports_a_dead_connector(armed, capsys):
    fake.snapshot = lambda a: (_ for _ in ()).throw(RuntimeError("token expired"))
    assert cli("rehearse") == 1 and "token expired" in capsys.readouterr().out


def test_rehearse_never_absorbs_a_change_without_approval(armed):
    fake.snap = {"filters": ["evil"]}
    cli("rehearse", answers=["n", "n"])
    assert open_vault()["baselines"]["mail"].get("filters", []) == []


def test_export_refuses_same_device_as_keyfile(armed, tmp_path):
    assert cli("export", str(tmp_path / "copy.vault")) != 0


def test_release_marks_account(armed):
    fake.release = lambda a: "temp-pass-123456789"
    assert cli("release", "--user", "mail", answers=["y"]) == 0 and "mail" in open_vault()["released"]


def test_map_names_the_root(armed, capsys):
    cli("map")
    assert "Can reset the most: mail" in capsys.readouterr().out


# -- decisions -----------------------------------------------------------

def test_outcome_round_trips_through_json():
    st = Step("a", "x", Phase.PURGE, Tier.GUIDED, "T", "http://l", WatchPolicy.REAPPLY, 3600)
    o = Outcome([Result(st, Status.LOCKED, Evidence.OWNER_CONFIRMED, "d", 5.0),
                 Result(replace(st, action="y"), Status.NEEDS_YOU, None, "", 6.0)], {"a": ["f: 1"]}, 1.0)
    back = outcome_from_json(json.loads(json.dumps(outcome_to_json(o))))
    assert back == o and isinstance(back.results[0].status, Status) and isinstance(back.results[0].step.phase, Phase)


def test_press_saves_outcome_that_watch_and_report_can_read(armed, patch_watch, capsys):
    cli("press", "--all")
    out = outcome_from_json(open_vault()["last_outcome"])
    assert any(r.status is Status.LOCKED for r in out.results)
    assert cli("report") == 0 and "## Locked" in capsys.readouterr().out
    assert cli("watch") == 0 and patch_watch.call_count == 2


def test_user_ids_are_lower_cased(armed, patch_watch):
    assert cli("press", "--user", "MAIL") == 0 and "mail/freeze" in fake.ran


def test_untargeted_root_is_reported_reopenable(armed, patch_watch):
    cli("press", "--user", "bank")
    assert "re-openable from mail" in report_path.read_text()
    assert not any(k.startswith("mail/") for k in fake.ran)


def test_report_files_and_log_are_private(armed, patch_watch):
    cli("press", "--all")
    for p in (report_path, Path(f"{vpath}.report.json"), log_path):
        assert stat.S_IMODE(p.stat().st_mode) == 0o600


def test_press_saves_outcome_even_when_interrupted_in_guided_step(armed, patch_watch):
    fake.steps.append(Step("", "g", Phase.PURGE, Tier.GUIDED, "Guided"))
    assert cli("press", "--all", answers=[]) == 0  # EOF at the first prompt
    assert "last_outcome" in open_vault() and report_path.exists()


def test_press_warns_when_vault_copy_is_stale(armed, patch_watch, capsys):
    key = kpath.read_bytes()
    d = open_vault()
    vault.save(vpath, d, PW, key)
    with patch("panic.cli.datetime") as dt:
        dt.now.return_value = __import__("datetime").datetime(2099, 1, 1, tzinfo=__import__("datetime").timezone.utc)
        dt.fromisoformat = __import__("datetime").datetime.fromisoformat
        cli("press", "--user", "mail")
    assert "stale" in capsys.readouterr().err


def test_same_device_warning_goes_to_stderr_without_changing_exit(armed, capsys):
    assert cli("map") == 0 and "same device" in capsys.readouterr().err


def test_watch_hours_count_from_the_press(armed, patch_watch):
    cli("press", "--all")
    assert 23.9 < patch_watch.call_args.kwargs["hours"] <= 24
    d = open_vault()
    d["last_outcome"]["started_at"] = time.time() - 25 * 3600
    vault.save(vpath, d, PW, kpath.read_bytes())
    patch_watch.reset_mock()
    assert cli("watch") == 0 and not patch_watch.called


def test_watch_ctrl_c_stops_cleanly_and_updates_log_head(armed, monkeypatch, capsys):
    monkeypatch.setattr(executor, "watch", MagicMock())
    cli("press", "--all")
    before = open_vault()["log_head"]

    def interrupted(results, conns, accounts, baselines, released, logfn, hours):
        logfn({"event": "changed"})
        raise KeyboardInterrupt

    monkeypatch.setattr(executor, "watch", interrupted)
    assert cli("watch") == 0 and "Watch stopped" in capsys.readouterr().out
    assert open_vault()["log_head"] == log.head(log_path) != before


def test_watch_sees_releases_made_while_it_runs(armed, patch_watch):
    cli("press", "--all")
    reload = patch_watch.call_args.args[4]
    assert reload() == set()
    fake.release = lambda a: "pw"
    cli("release", "--user", "mail", answers=["y"])
    assert reload() == {"mail"}


def test_report_warns_when_log_was_edited(armed, patch_watch, capsys):
    cli("press", "--all")
    capsys.readouterr()
    cli("report")
    assert "audit log has been changed" not in capsys.readouterr().err
    log_path.write_text(log_path.read_text().replace('"freeze"', '"fr33ze"', 1))
    cli("report")
    assert "audit log has been changed" in capsys.readouterr().err


def test_report_warns_when_log_head_differs_from_vault(armed, patch_watch, capsys):
    cli("press", "--all")
    log.append(log_path, {"event": "extra"})  # valid chain, but not what the press recorded
    capsys.readouterr()
    cli("report")
    assert "audit log has been changed" in capsys.readouterr().err


def test_missing_vault_is_one_line_exit_1(bare, capsys):
    kpath.write_bytes(b"k" * 32)
    assert cli("map") == 1
    err = capsys.readouterr().err.strip().splitlines()
    assert len(err) == 1 and "No vault" in err[0]


def test_missing_keyfile_is_one_line_exit_1(armed, capsys):
    kpath.unlink()
    assert cli("map") == 1 and capsys.readouterr().err.strip().count("\n") == 0


def test_usage_error_is_one_line_exit_1(armed, capsys):
    assert cli("release") == 1 and len(capsys.readouterr().err.strip().splitlines()) == 1


def test_release_refused_for_provider_without_release(armed, capsys):
    assert cli("release", "--user", "mail", answers=["y"]) == 1
    assert "released" not in capsys.readouterr().out and open_vault()["released"] == []


def test_release_declined_changes_nothing(armed):
    fake.release = lambda a: "pw"
    assert cli("release", "--user", "mail", answers=["n"]) == 1 and open_vault()["released"] == []


def test_export_copies_the_vault_when_elsewhere(armed, tmp_path):
    with patch("panic.cli._same_device", return_value=False):
        assert cli("export", str(tmp_path / "copy.vault")) == 0
    assert (tmp_path / "copy.vault").read_bytes() == vpath.read_bytes()


# -- arm -----------------------------------------------------------------

def arm_personal(*extra, answers, token=None, **kw):
    f = FakeConnector(provider="google_personal")
    f.snap = {"filters": ["f1"]}
    calls = []

    def authorize(p):
        calls.append(p)
        return token or {"refresh_token": "r"}

    rc = cli("arm", "--personal", "Me@Example.com", "--client-secrets", "cs.json", *extra, answers=answers,
             connectors={"google_personal": f}, authorize=authorize, **kw)
    return rc, calls


def test_arm_refusal_writes_nothing_and_starts_no_sign_in(bare):
    rc, calls = arm_personal(answers=["n"])
    assert rc == 1 and calls == [] and not vpath.exists() and not kpath.exists() and not vpath.parent.exists()


def test_arm_creates_vault_and_keyfile_and_records_baseline(bare, capsys):
    rc, calls = arm_personal(answers=["y", "y"])
    assert rc == 0 and calls == [Path("cs.json")]
    d = open_vault()
    assert d["accounts"] == [{"id": "me@example.com", "provider": "google_personal", "protected": False}]
    assert d["baselines"]["me@example.com"] == {"filters": ["f1"]}
    assert d["credentials"]["google_personal"]["me@example.com"] == {"refresh_token": "r"}
    assert stat.S_IMODE(kpath.stat().st_mode) == 0o600 and stat.S_IMODE(vpath.parent.stat().st_mode) == 0o700
    assert f"Key file written to {kpath}" in capsys.readouterr().out


def test_arm_declined_baseline_saves_nothing(bare):
    rc, _ = arm_personal(answers=["y", "n"])
    assert rc == 1 and not vpath.exists() and not kpath.exists()


def test_arm_rejects_mismatched_or_empty_passphrase(bare):
    with patch("getpass.getpass", side_effect=["a", "b"]), patch("builtins.input", return_value="y"):
        assert main(["--vault", str(vpath), "--keyfile", str(kpath), "arm", "--personal", "x@y.z",
                     "--client-secrets", "c"], connectors={}, authorize=lambda p: {}) == 1
    assert not vpath.exists()
    assert cli("arm", "--personal", "x@y.z", "--client-secrets", "c", passphrase="", answers=["y"]) == 1


def test_arm_second_account_asks_who_can_reset_it_and_rejects_unknown(armed):
    f = FakeConnector(provider="google_personal")
    rc = cli("arm", "--personal", "new@x.com", "--client-secrets", "c", connectors={"google_personal": f},
             authorize=lambda p: {"t": 1}, answers=["y", "y", "ghost", "MAIL"])
    assert rc == 0 and ["mail", "new@x.com"] in open_vault()["edges"]


def test_reconnect_fails_for_unarmed_account(armed):
    calls = []
    rc = cli("arm", "--personal", "ghost@x.com", "--reconnect", "--client-secrets", "c",
             authorize=lambda p: calls.append(p), answers=[])
    assert rc == 1 and calls == []


def test_reconnect_replaces_only_the_token(armed):
    cli("arm", "--personal", "new@x.com", "--client-secrets", "c",
        connectors={"google_personal": FakeConnector(provider="google_personal")},
        authorize=lambda p: {"t": 1}, answers=["y", "y", ""])
    before = open_vault()
    assert cli("arm", "--personal", "NEW@x.com", "--reconnect", "--client-secrets", "c",
               authorize=lambda p: {"t": 2}, answers=[]) == 0
    after = open_vault()
    assert after["credentials"]["google_personal"]["new@x.com"] == {"t": 2}
    assert after["accounts"] == before["accounts"] and after["baselines"] == before["baselines"]


class FakeWorkspace(FakeConnector):
    def __init__(self, users, snaps):
        super().__init__(provider="google_workspace", steps=_steps())
        self._users, self.snaps = users, snaps

    def users(self):
        return self._users

    def snapshot(self, account):
        s = self.snaps[account.id]
        if isinstance(s, Exception):
            raise s
        return s


def test_arm_workspace_protects_admin_records_edges_and_warns(bare, capsys):
    key = bare / "sa.json"
    key.write_text(json.dumps({"private_key": "x"}))
    ws = FakeWorkspace(["Admin@d.com", "a@d.com", "b@d.com", "c@d.com"], {
        "a@d.com": {"recovery": ["email:Admin@d.com"], "forwarding": ["evil@x.com"]},
        "b@d.com": {"recovery": ["email:a@d.com", "phone:+1"]},
        "c@d.com": RuntimeError("denied"),
    })
    rc = cli("arm", "--workspace", "--sa-key", str(key), "--admin", "ADMIN@d.com", "--domain", "d.com",
             connectors={"google_workspace": ws}, answers=[])
    cap = capsys.readouterr()
    d = open_vault()
    by = {a["id"]: a for a in d["accounts"]}
    assert rc == 0 and by["admin@d.com"]["protected"] and not by["a@d.com"]["protected"]
    assert "admin@d.com" not in d["baselines"] and "c@d.com" not in d["baselines"]
    assert ["admin@d.com", "a@d.com"] in d["edges"] and ["a@d.com", "b@d.com"] in d["edges"]
    assert "evil@x.com" not in cap.out and "c@d.com" in cap.err
    assert d["credentials"]["google_workspace"]["admin"] == "admin@d.com"


def test_rehearse_workspace_shows_flags_only_and_asks_nothing(armed, capsys):
    d = open_vault()
    d["accounts"].append({"id": "w@d.com", "provider": "google_workspace", "protected": False})
    d["baselines"]["w@d.com"] = {}
    vault.save(vpath, d, PW, kpath.read_bytes())
    ws = FakeWorkspace([], {"w@d.com": {"forwarding": ["secret@x.com"], "filters": ["f"]}})
    cli("rehearse", connectors={"google_workspace": ws}, answers=[])
    out = capsys.readouterr().out
    assert "w@d.com: changed since baseline: forwarding" in out and "secret@x.com" not in out and "filters:" not in out
    assert open_vault()["baselines"]["w@d.com"] == {}


def test_rehearse_approved_change_replaces_baseline_and_prints_plan(armed, capsys):
    fake.snap = {"filters": ["ok"]}
    cli("rehearse", answers=["y", "n"])
    d = open_vault()["baselines"]
    assert d["mail"] == {"filters": ["ok"]} and d["bank"] == {}
    assert "mail: Freeze" in capsys.readouterr().out
