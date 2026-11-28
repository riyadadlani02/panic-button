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
from panic.model import Account, Evidence, Finding, Outcome, Severity, Phase, Result, Status, Step, Tier, WatchPolicy

PW = "pw"
CLIENT = {"installed": {"client_id": "i"}}
fake = vpath = kpath = log_path = cs = None
REAL_PRESS = executor.press


def _steps():
    return [Step("", "freeze", Phase.FREEZE, Tier.API, "Freeze"), Step("", "purge", Phase.PURGE, Tier.API, "Purge")]


@pytest.fixture
def bare(tmp_path):
    """Paths set, no vault yet."""
    global fake, vpath, kpath, log_path, cs
    fake = FakeConnector(steps=_steps())
    cs = tmp_path / "cs.json"
    cs.write_text(json.dumps(CLIENT))
    vpath, kpath = tmp_path / "vault" / "panic.vault", tmp_path / "key"
    log_path = Path(f"{vpath}.log.jsonl")
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


def reports(ext="md"):
    return sorted(vpath.parent.glob(f"{vpath.name}.report-*.{ext}"))


def latest_report():
    return reports()[-1]


def press_at(monkeypatch, t):
    """The next press starts at time t."""
    monkeypatch.setattr(executor, "press", lambda *a, **k: REAL_PRESS(*a, now=lambda: t, **k))


def cli(*args, passphrase=PW, answers=(), connectors=None, authorize=None, whoami=None, **extra):
    it = iter(answers)
    if whoami is None:  # by default the owner signs in as the account being armed
        who = args[args.index("--personal") + 1] if "--personal" in args else ""
        whoami = lambda token: who

    def fake_input(prompt=""):
        try:
            return next(it)
        except StopIteration:
            raise EOFError

    with patch("getpass.getpass", return_value=passphrase), patch("builtins.input", fake_input):
        return main(["--vault", str(vpath), "--keyfile", str(kpath), *args],
                    connectors={"fake": fake} if connectors is None else connectors, authorize=authorize,
                    whoami=whoami, **extra)


# -- the brief's tests ---------------------------------------------------

def test_dry_run_changes_nothing_and_writes_no_outcome(armed):
    assert cli("press", "--all", "--dry-run") == 0 and fake.ran == [] and "outcomes" not in open_vault()
    assert reports() == []


def test_press_all_skips_protected_and_writes_report_and_log(armed, patch_watch):
    assert cli("press", "--all") == 0
    assert not any(k.startswith("boss/") for k in fake.ran)
    assert "## Locked" in latest_report().read_text() and log.verify(log_path) and patch_watch.called


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
    out = outcome_from_json(open_vault()["outcomes"][-1])
    assert any(r.status is Status.LOCKED for r in out.results)
    assert cli("report") == 0 and "## Locked" in capsys.readouterr().out
    assert cli("watch") == 0 and patch_watch.call_count == 2


def test_user_ids_are_lower_cased(armed, patch_watch):
    assert cli("press", "--user", "MAIL") == 0 and "mail/freeze" in fake.ran


def test_untargeted_root_is_reported_reopenable(armed, patch_watch):
    cli("press", "--user", "bank")
    assert "re-openable from mail" in latest_report().read_text()
    assert not any(k.startswith("mail/") for k in fake.ran)


def test_report_files_and_log_are_private(armed, patch_watch):
    cli("press", "--all")
    for p in (latest_report(), reports("json")[-1], log_path):
        assert stat.S_IMODE(p.stat().st_mode) == 0o600


def test_press_saves_outcome_even_when_interrupted_in_guided_step(armed, patch_watch):
    fake.steps.append(Step("", "g", Phase.PURGE, Tier.GUIDED, "Guided"))
    assert cli("press", "--all", answers=[]) == 0  # EOF at the first prompt
    assert "outcomes" in open_vault() and reports() != []


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
    d["outcomes"][-1]["started_at"] = time.time() - 25 * 3600
    vault.save(vpath, d, PW, kpath.read_bytes())
    patch_watch.reset_mock()
    assert cli("watch") == 0 and not patch_watch.called


def test_watch_ctrl_c_stops_cleanly_and_report_trusts_its_entries(armed, monkeypatch, capsys):
    monkeypatch.setattr(executor, "watch", MagicMock())
    cli("press", "--all")
    before = open_vault()["log_head"]

    def interrupted(results, conns, accounts, baselines, released, logfn, hours, **kw):
        logfn({"event": "changed", "account": "mail", "action": "freeze", "detail": "changed since lockdown"})
        raise KeyboardInterrupt

    monkeypatch.setattr(executor, "watch", interrupted)
    assert cli("watch") == 0 and "Watch stopped" in capsys.readouterr().out
    assert open_vault()["log_head"] == before != log.head(log_path)
    assert cli("report") == 0
    cap = capsys.readouterr()
    assert "audit log has been changed" not in cap.err
    assert "- `mail`: `freeze` changed (seen 1 times" in cap.out.split("## Still open")[1]


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
    lines = log_path.read_bytes().splitlines(keepends=True)
    log_path.write_bytes(b"".join(lines[:-1]))  # valid chain, but the press's last entry is gone
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

    def authorize(cfg, login_hint=None):
        calls.append((cfg, login_hint))
        return token or {"refresh_token": "r"}

    rc = cli("arm", "--personal", "Me@Example.com", "--client-secrets", str(cs), *extra, answers=answers,
             connectors={"google_personal": f}, authorize=authorize, **kw)
    return rc, calls


def test_arm_refusal_writes_nothing_and_starts_no_sign_in(bare):
    rc, calls = arm_personal(answers=["n"])
    assert rc == 1 and calls == [] and not vpath.exists() and not kpath.exists() and not vpath.parent.exists()


def test_arm_creates_vault_and_keyfile_and_records_baseline(bare, capsys):
    rc, calls = arm_personal(answers=["y", "y"])
    assert rc == 0 and calls == [(CLIENT, "me@example.com")]
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
                     "--client-secrets", str(cs)], connectors={}, authorize=lambda cfg, login_hint=None: {}) == 1
    assert not vpath.exists()
    assert cli("arm", "--personal", "x@y.z", "--client-secrets", str(cs), passphrase="", answers=["y"]) == 1


def test_arm_second_account_asks_who_can_reset_it_and_rejects_unknown(armed):
    f = FakeConnector(provider="google_personal")
    rc = cli("arm", "--personal", "new@x.com", "--client-secrets", str(cs), connectors={"google_personal": f},
             authorize=lambda cfg, login_hint=None: {"t": 1}, answers=["y", "y", "ghost", "MAIL"])
    assert rc == 0 and ["mail", "new@x.com"] in open_vault()["edges"]


def test_reconnect_fails_for_unarmed_account(armed):
    calls = []
    rc = cli("arm", "--personal", "ghost@x.com", "--reconnect", "--client-secrets", str(cs),
             authorize=lambda cfg, login_hint=None: calls.append(cfg), answers=[])
    assert rc == 1 and calls == []


def test_reconnect_replaces_only_the_token(armed):
    cli("arm", "--personal", "new@x.com", "--client-secrets", str(cs),
        connectors={"google_personal": FakeConnector(provider="google_personal")},
        authorize=lambda cfg, login_hint=None: {"t": 1}, answers=["y", "y", ""])
    before = open_vault()
    assert cli("arm", "--personal", "NEW@x.com", "--reconnect", "--client-secrets", str(cs),
               authorize=lambda cfg, login_hint=None: {"t": 2}, answers=[]) == 0
    after = open_vault()
    assert after["credentials"]["google_personal"]["new@x.com"] == {"t": 2}
    assert after["accounts"] == before["accounts"] and after["baselines"] == before["baselines"]


def builtin_clients(monkeypatch, tmp_path, **ids):
    """The sign-in apps the tool ships with, as `PANIC_OAUTH_CLIENTS` names them."""
    p = tmp_path / "oauth_clients.json"
    p.write_text(json.dumps(ids))
    monkeypatch.setenv("PANIC_OAUTH_CLIENTS", str(p))


BUILTIN = {"installed": {"client_id": "shipped"}}


def test_arm_personal_with_no_address_uses_the_builtin_client_and_arms_the_signed_in_address(bare, monkeypatch):
    builtin_clients(monkeypatch, bare, google=BUILTIN)
    calls = []
    rc = cli("arm", "--personal", connectors={"google_personal": FakeConnector(provider="google_personal")},
             authorize=lambda cfg, login_hint=None: calls.append((cfg, login_hint)) or {"t": 1},
             whoami=lambda token: "Me@Example.com", answers=["y", "y"])
    d = open_vault()
    assert rc == 0 and calls == [(BUILTIN, None)]
    assert d["accounts"] == [{"id": "me@example.com", "provider": "google_personal", "protected": False}]
    assert d["credentials"]["google_personal"] == {"me@example.com": {"t": 1}} and d["credentials"]["google_client"] == BUILTIN


def test_arm_personal_with_no_address_refuses_a_signed_in_address_armed_under_another_provider(armed, monkeypatch, capsys):
    builtin_clients(monkeypatch, vpath.parent.parent, google=BUILTIN)
    rc = cli("arm", "--personal", authorize=lambda cfg, login_hint=None: {"t": 1}, whoami=lambda token: "MAIL",
             answers=["y", "y", ""])
    assert rc == 1 and "already armed" in capsys.readouterr().err
    assert "google_personal" not in open_vault()["credentials"]


def test_reconnect_with_no_address_reconnects_the_signed_in_account(armed):
    cli("arm", "--personal", "new@x.com", "--client-secrets", str(cs),
        connectors={"google_personal": FakeConnector(provider="google_personal")},
        authorize=lambda cfg, login_hint=None: {"t": 1}, answers=["y", "y", ""])
    calls = []
    assert cli("arm", "--personal", "--reconnect", whoami=lambda token: "New@x.com",
               authorize=lambda cfg, login_hint=None: calls.append((cfg, login_hint)) or {"t": 2}) == 0
    assert calls == [(CLIENT, None)] and open_vault()["credentials"]["google_personal"]["new@x.com"] == {"t": 2}


def test_arm_personal_with_no_builtin_client_still_needs_the_client_file(bare, monkeypatch, capsys):
    calls = []
    assert cli("arm", "--personal", whoami=lambda t: "x@y.z", answers=["y"],
               authorize=lambda cfg, login_hint=None: calls.append(cfg)) == 1
    assert calls == [] and "--client-secrets FILE is required" in capsys.readouterr().err and not vpath.exists()


class FakeWorkspace(FakeConnector):
    def __init__(self, users, snaps):
        super().__init__(provider="google_workspace", steps=_steps())
        self._users, self.snaps = users, snaps

    def users(self):
        return self._users

    def verify_admin(self):
        pass

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


def test_rehearse_workspace_shows_flags_and_filter_count_only(armed, capsys):
    d = open_vault()
    d["accounts"].append({"id": "w@d.com", "provider": "google_workspace", "protected": False})
    d["baselines"]["w@d.com"] = {}
    vault.save(vpath, d, PW, kpath.read_bytes())
    ws = FakeWorkspace([], {"w@d.com": {"forwarding": ["secret@x.com"], "filters": ["subject:hidden"]}})
    cli("rehearse", connectors={"google_workspace": ws}, answers=["n"])
    out = capsys.readouterr().out
    assert "w@d.com: changed since baseline: forwarding, filters: 1 not in baseline (contents withheld)" in out
    assert "secret@x.com" not in out and "hidden" not in out
    assert open_vault()["baselines"]["w@d.com"] == {}


def test_rehearse_approved_change_replaces_baseline_and_prints_plan(armed, capsys):
    fake.snap = {"filters": ["ok"]}
    cli("rehearse", answers=["y", "n"])
    d = open_vault()["baselines"]
    assert d["mail"] == {"filters": ["ok"]} and d["bank"] == {}
    assert "mail: Freeze" in capsys.readouterr().out


# -- review fixes --------------------------------------------------------

def test_report_still_printed_when_vault_save_fails(armed, patch_watch, monkeypatch, capsys):
    real = vault.save
    monkeypatch.setattr("panic.vault.save", lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")))
    assert cli("press", "--all") == 0
    cap = capsys.readouterr()
    assert "## Locked" in cap.out and "disk full" in cap.err and patch_watch.called
    monkeypatch.setattr("panic.vault.save", real)


def test_report_still_printed_when_report_write_fails(armed, patch_watch, monkeypatch, capsys):
    def boom(path, data, exclusive=False):
        raise OSError("read-only")
    monkeypatch.setattr("panic.cli._private_write", boom)
    assert cli("press", "--all") == 0
    cap = capsys.readouterr()
    assert "## Locked" in cap.out and "read-only" in cap.err and "outcomes" in open_vault()


def test_personal_arm_cannot_replace_protected_account(armed, capsys):
    before = vpath.read_bytes()
    calls = []
    rc = cli("arm", "--personal", "boss", "--client-secrets", str(cs), answers=["y"],
             connectors={"google_personal": FakeConnector(provider="google_personal")},
             authorize=lambda cfg, login_hint=None: calls.append(cfg))
    assert rc == 1 and calls == [] and vpath.read_bytes() == before
    assert sum(l.startswith("error:") for l in capsys.readouterr().err.splitlines()) == 1


def test_personal_arm_cannot_change_a_provider(armed):
    before = vpath.read_bytes()
    assert cli("arm", "--personal", "mail", "--client-secrets", str(cs), answers=["y"],
               authorize=lambda cfg, login_hint=None: {}) == 1 and vpath.read_bytes() == before


def test_workspace_arm_refuses_admin_armed_as_other_provider(armed):
    (bare_dir := vpath.parent / "sa.json").write_text("{}")
    before = vpath.read_bytes()
    ws = FakeWorkspace(["boss"], {})
    assert cli("arm", "--workspace", "--sa-key", str(bare_dir), "--admin", "mail", "--domain", "d",
               connectors={"google_workspace": ws}) == 1 and vpath.read_bytes() == before


def test_workspace_arm_keeps_existing_protected_flag(armed):
    (sa := vpath.parent / "sa.json").write_text("{}")
    d = open_vault()
    d["accounts"].append({"id": "old@d.com", "provider": "google_workspace", "protected": True})
    vault.save(vpath, d, PW, kpath.read_bytes())
    ws = FakeWorkspace(["old@d.com", "adm@d.com"], {"old@d.com": {}})
    assert cli("arm", "--workspace", "--sa-key", str(sa), "--admin", "adm@d.com", "--domain", "d.com",
               connectors={"google_workspace": ws}) == 0
    assert {a["id"]: a["protected"] for a in open_vault()["accounts"]}["old@d.com"] is True


def test_malformed_sa_key_is_one_line(bare, capsys):
    (sa := bare / "sa.json").write_text("{not json")
    assert cli("arm", "--workspace", "--sa-key", str(sa), "--admin", "a@d.com", "--domain", "d.com") == 1
    err = capsys.readouterr().err.strip().splitlines()
    assert len(err) == 1 and "service-account key" in err[0] and not vpath.exists()


def test_failing_workspace_listing_is_one_line(bare, capsys):
    (sa := bare / "sa.json").write_text("{}")
    ws = FakeWorkspace([], {})
    ws.users = lambda: (_ for _ in ()).throw(RuntimeError("delegation missing"))
    assert cli("arm", "--workspace", "--sa-key", str(sa), "--admin", "a@d.com", "--domain", "d.com",
               connectors={"google_workspace": ws}) == 1
    assert "delegation missing" in capsys.readouterr().err and not vpath.exists()


def test_failing_sign_in_is_one_line(bare, capsys):
    def authorize(cfg, login_hint=None):
        raise RuntimeError("consent denied")
    rc = cli("arm", "--personal", "x@y.z", "--client-secrets", str(cs), answers=["y"], authorize=authorize)
    err = capsys.readouterr().err.strip().splitlines()
    assert rc == 1 and len(err) == 1 and "consent denied" in err[0] and not vpath.exists()


def test_wrong_length_existing_keyfile_is_one_line(bare, capsys):
    kpath.write_bytes(b"short")
    assert cli("arm", "--personal", "x@y.z", "--client-secrets", str(cs), answers=["y"], authorize=lambda cfg, login_hint=None: {}) == 1
    assert "key file" in capsys.readouterr().err and not vpath.exists()


def _ws_armed(armed):
    d = open_vault()
    d["accounts"].append({"id": "w@d.com", "provider": "google_workspace", "protected": False})
    d["baselines"]["w@d.com"] = {}
    vault.save(vpath, d, PW, kpath.read_bytes())
    return FakeWorkspace([], {"w@d.com": {"filters": ["from:x subject:secret", "b"], "forwarding": ["f@x.com"]}})


def test_workspace_filter_contents_are_withheld_in_dry_run_and_report(armed, patch_watch, capsys):
    ws = _ws_armed(armed)
    ws.snap = ws.snaps["w@d.com"]
    ws.snapshot = lambda a: ws.snaps[a.id]
    conns = {"fake": fake, "google_workspace": ws}
    cli("press", "--all", "--dry-run", connectors=conns)
    out = capsys.readouterr().out
    assert "filters: 2 not in baseline (contents withheld)" in out and "secret" not in out and "forwarding: f@x.com" in out
    cli("press", "--all", connectors=conns)
    out = capsys.readouterr().out
    assert "contents withheld" in out and "secret" not in out and "secret" not in latest_report().read_text()
    assert "secret" in json.dumps(open_vault()["outcomes"][-1])


def test_rehearse_without_approved_change_does_not_resave_vault(armed):
    before = vpath.read_bytes()
    assert cli("rehearse") == 0 and vpath.read_bytes() == before


# -- final-review fixes --------------------------------------------------

def test_workspace_removed_filters_are_withheld_in_the_report(armed, patch_watch, capsys):
    ws = _ws_armed(armed)
    ws.snapshot = lambda a: {"filters": []} if "w@d.com/purge" in ws.ran else {"filters": ["from:x subject:secret"]}
    cli("press", "--user", "w@d.com", connectors={"fake": fake, "google_workspace": ws})
    out = capsys.readouterr().out
    removed = out.split("## Removed by this press")[1]
    assert "filters: 1 not in baseline (contents withheld)" in removed and "secret" not in out


def test_press_prints_phase_progress_to_stderr(armed, patch_watch, capsys):
    cli("press", "--all")
    err = capsys.readouterr().err
    assert "Freeze:" in err and "Purge:" in err


def test_arm_refuses_a_different_signed_in_account(bare, capsys):
    rc, _ = arm_personal(answers=["y", "y"], whoami=lambda token: "Other@Example.com")
    err = capsys.readouterr().err.strip().splitlines()
    assert rc == 1 and len(err) == 1 and "other@example.com" in err[0].lower() and "me@example.com" in err[0]
    assert not vpath.exists()


def test_arm_accepts_the_same_account_in_another_case(bare):
    rc, _ = arm_personal(answers=["y", "y"], whoami=lambda token: "ME@example.COM")
    assert rc == 0


def test_reconnect_refuses_a_different_signed_in_account(armed):
    cli("arm", "--personal", "new@x.com", "--client-secrets", str(cs),
        connectors={"google_personal": FakeConnector(provider="google_personal")},
        authorize=lambda cfg, login_hint=None: {"t": 1}, answers=["y", "y", ""])
    before = open_vault()["credentials"]
    assert cli("arm", "--personal", "new@x.com", "--reconnect", "--client-secrets", str(cs),
               authorize=lambda cfg, login_hint=None: {"t": 2}, whoami=lambda t: "mallory@x.com") == 1
    assert open_vault()["credentials"] == before


def test_reconnect_during_a_press_survives_the_press_save(armed, patch_watch):
    d = open_vault()
    d["accounts"].append({"id": "p@x.com", "provider": "google_personal", "protected": False})
    d["credentials"] = {"google_personal": {"p@x.com": {"t": 1}}, "google_client": CLIENT}
    vault.save(vpath, d, PW, kpath.read_bytes())
    orig = fake.run

    def run(step, baseline):  # a second process reconnects while the press is running
        if step.account == "mail" and step.action == "purge":
            assert main(["--vault", str(vpath), "--keyfile", str(kpath), "arm", "--personal", "p@x.com",
                         "--reconnect"], authorize=lambda cfg, login_hint=None: {"t": 2},
                        whoami=lambda t: "p@x.com") == 0
        orig(step, baseline)

    fake.run = run
    cli("press", "--user", "mail")
    assert open_vault()["credentials"]["google_personal"]["p@x.com"] == {"t": 2}


def test_reconnect_uses_the_stored_client_config(bare):
    arm_personal(answers=["y", "y"])
    assert open_vault()["credentials"]["google_client"] == CLIENT
    got = []
    assert cli("arm", "--personal", "me@example.com", "--reconnect",
               authorize=lambda cfg, login_hint=None: got.append(cfg) or {"t": 2}) == 0
    assert got == [CLIENT] and open_vault()["credentials"]["google_personal"]["me@example.com"] == {"t": 2}


def test_watch_picks_up_a_new_token_and_an_approved_baseline(armed, patch_watch):
    cli("press", "--user", "mail")
    d = open_vault()
    d["credentials"] = {"google_personal": {"p@x.com": {"t": 1}}}
    vault.save(vpath, d, PW, kpath.read_bytes())
    with patch("getpass.getpass", return_value=PW):
        assert main(["--vault", str(vpath), "--keyfile", str(kpath), "watch"]) == 0
    _, conns, _, baselines, reload = patch_watch.call_args.args[:5]
    d = open_vault()
    d["credentials"]["google_personal"]["p@x.com"] = {"t": 2}
    d["baselines"]["mail"] = {"filters": ["approved"]}
    vault.save(vpath, d, PW, kpath.read_bytes())
    reload()
    assert conns["google_personal"]._tokens == {"p@x.com": {"t": 2}} and baselines["mail"] == {"filters": ["approved"]}


def test_press_release_press_again_and_the_watch_re_suspends(armed, patch_watch):
    fake.steps.append(Step("", "suspend", Phase.FREEZE, Tier.API, "Suspend", watch=WatchPolicy.REAPPLY))
    fake.release = lambda a: "pw"
    cli("press", "--user", "mail")
    cli("release", "--user", "mail", answers=["y"])
    cli("press", "--user", "mail")
    results, conns, accounts, baselines, released = patch_watch.call_args.args[:5]
    fake.state["mail/suspend"] = False
    fake.ran.clear()
    executor.watch_once(results, conns, accounts, baselines, released(), lambda e: None)
    assert "mail/suspend" in fake.ran


def test_a_second_press_keeps_the_first_record_and_report(armed, patch_watch, monkeypatch):
    press_at(monkeypatch, time.time() - 7200)
    cli("press", "--user", "mail")
    first = latest_report()
    text = first.read_text()
    press_at(monkeypatch, time.time() - 3600)
    cli("press", "--user", "bank")
    d = open_vault()
    assert len(d["outcomes"]) == 2 and d["outcomes"][0]["touched"].keys() == {"mail"}
    assert len(reports()) == 2 and first.read_text() == text and latest_report() != first
    assert stat.S_IMODE(latest_report().stat().st_mode) == 0o600


def test_report_rerenders_the_latest_press_and_lists_earlier_ones(armed, patch_watch, monkeypatch, capsys):
    press_at(monkeypatch, time.time() - 7200)
    cli("press", "--user", "mail")
    press_at(monkeypatch, time.time() - 3600)
    cli("press", "--user", "bank")
    first, second = reports()
    second.unlink()
    capsys.readouterr()
    assert cli("report") == 0
    out = capsys.readouterr().out
    assert reports() == [first, second] and "re-openable from mail" in second.read_text()
    assert f"Earlier reports: {first.name}" in out


def test_watch_covers_recent_presses_and_a_later_failure_keeps_the_earlier_lock(armed, patch_watch, monkeypatch):
    fake.steps.append(Step("", "old", Phase.PURGE, Tier.API, "Old"))
    press_at(monkeypatch, time.time() - 30 * 3600)  # outside the window
    cli("press", "--user", "bank")
    fake.steps.pop()
    early, late = time.time() - 7200, time.time() - 3600
    press_at(monkeypatch, early)
    cli("press", "--all")
    fake.fail = {"mail/purge"}
    press_at(monkeypatch, late)
    cli("press", "--user", "mail")
    results = patch_watch.call_args.args[0]
    assert {(r.step.account, r.step.action): (r.status, r.at) for r in results} == {
        ("mail", "freeze"): (Status.LOCKED, late), ("mail", "purge"): (Status.LOCKED, early),
        ("bank", "freeze"): (Status.LOCKED, early), ("bank", "purge"): (Status.LOCKED, early)}
    assert 22.9 < patch_watch.call_args.kwargs["hours"] <= 23


def test_progress_is_saved_before_the_walkthrough(armed, patch_watch):
    fake.steps.append(Step("", "g", Phase.PURGE, Tier.GUIDED, "Guided"))
    seen = []

    def answers():  # runs at the first guided prompt, as if the process died there
        seen.append((open_vault()["outcomes"][-1], reports()))
        yield "y"

    cli("press", "--user", "mail", answers=answers())
    saved, files = seen[0]
    assert [r["step"]["action"] for r in saved["results"]] == ["freeze", "purge"] and files
    assert len(open_vault()["outcomes"]) == 1 and len(open_vault()["outcomes"][0]["results"]) == 3


def test_one_user_press_reads_no_other_account(armed, patch_watch):
    reads = []
    snap, check = fake.snapshot, fake.check
    fake.snapshot = lambda a: reads.append(a.id) or snap(a)
    fake.check = lambda step, baseline: reads.append(step.account) or check(step, baseline)
    cli("press", "--user", "bank")
    assert reads and set(reads) == {"bank"}


def test_removed_prints_one_accounts_items_unredacted(armed, patch_watch, capsys):
    ws = _ws_armed(armed)
    ws.snapshot = lambda a: {"filters": []} if "w@d.com/purge" in ws.ran else {"filters": ["from:x subject:secret"]}
    conns = {"fake": fake, "google_workspace": ws}
    cli("press", "--user", "w@d.com", connectors=conns)
    capsys.readouterr()
    assert cli("removed", "--user", "W@d.com", connectors=conns) == 0
    out = capsys.readouterr().out
    assert out.count("filters: from:x subject:secret") == 2  # removed, and outside the baseline
    assert cli("removed", "--user", "boss") == 1 and cli("removed", "--user", "nobody") == 1


def test_rehearse_workspace_accepts_current_settings_on_yes(armed):
    d = open_vault()
    d["accounts"].append({"id": "w@d.com", "provider": "google_workspace", "protected": False})
    d["baselines"]["w@d.com"] = {}
    vault.save(vpath, d, PW, kpath.read_bytes())
    ws = FakeWorkspace([], {"w@d.com": {"delegates": ["pa@d.com"]}})
    prompts = []
    with patch("getpass.getpass", return_value=PW), \
            patch("builtins.input", lambda p="": prompts.append(p) or "y"):
        main(["--vault", str(vpath), "--keyfile", str(kpath), "rehearse"], connectors={"google_workspace": ws})
    assert prompts == ["Accept w@d.com's current settings as the new baseline? [y/N] "]
    assert open_vault()["baselines"]["w@d.com"] == {"delegates": ["pa@d.com"]}


def test_workspace_arm_refuses_an_admin_that_is_not_a_primary_super_admin(bare, capsys):
    (sa := bare / "sa.json").write_text("{}")
    ws = FakeWorkspace(["a@d.com"], {"a@d.com": {}})
    ws.verify_admin = lambda: (_ for _ in ()).throw(ValueError("alias@d.com is not a super admin's primary address"))
    assert cli("arm", "--workspace", "--sa-key", str(sa), "--admin", "alias@d.com", "--domain", "d.com",
               connectors={"google_workspace": ws}) == 1
    err = capsys.readouterr().err.strip().splitlines()
    assert len(err) == 1 and "primary address" in err[0] and not vpath.exists() and ws.ran == []


def test_workspace_re_arm_keeps_existing_baselines_and_skips_other_providers(armed, capsys):
    (sa := vpath.parent / "sa.json").write_text("{}")
    first = FakeWorkspace(["old@d.com", "gap@d.com"], {"old@d.com": {"filters": ["ok"]}, "gap@d.com": RuntimeError("x")})
    cli("arm", "--workspace", "--sa-key", str(sa), "--admin", "adm@d.com", "--domain", "d.com",
        connectors={"google_workspace": first})
    accounts_before = {a["id"]: a for a in open_vault()["accounts"]}
    again = FakeWorkspace(["old@d.com", "gap@d.com", "new@d.com", "mail"],
                          {"old@d.com": {"filters": ["ok", "attacker"]}, "gap@d.com": {"filters": []},
                           "new@d.com": {"filters": ["n"]}, "mail": {"filters": ["m"]}})
    capsys.readouterr()
    assert cli("arm", "--workspace", "--sa-key", str(sa), "--admin", "adm@d.com", "--domain", "d.com",
               connectors={"google_workspace": again}) == 0
    d = open_vault()
    assert d["baselines"]["old@d.com"] == {"filters": ["ok"]}
    assert d["baselines"]["gap@d.com"] == {"filters": []} and d["baselines"]["new@d.com"] == {"filters": ["n"]}
    by = {a["id"]: a for a in d["accounts"]}
    assert by["mail"]["provider"] == "fake" and d["baselines"]["mail"] == {}
    assert all(by[i] == accounts_before[i] for i in accounts_before)
    assert "mail" in capsys.readouterr().err


def test_release_records_the_id_before_unsuspending(armed, capsys):
    seen = []
    fake.release = lambda a: seen.append(open_vault()["released"]) or "temp-pw"
    assert cli("release", "--user", "mail", answers=["y"]) == 0
    assert seen == [["mail"]] and "temp-pw" in capsys.readouterr().out


def test_failed_release_is_taken_back_out_of_released(armed, capsys):
    fake.release = lambda a: (_ for _ in ()).throw(RuntimeError("api down"))
    assert cli("release", "--user", "mail", answers=["y"]) == 1
    assert open_vault()["released"] == open_vault()["unguarded"] == [] and "api down" in capsys.readouterr().err


def test_guard_names_an_exception_without_a_message(capsys):
    from panic.cli import _guard

    def interrupted():
        raise KeyboardInterrupt
    _guard("save", interrupted)
    assert "could not save: KeyboardInterrupt" in capsys.readouterr().err


def test_unreadable_log_does_not_hide_the_report(armed, patch_watch, monkeypatch, capsys):
    monkeypatch.setattr(log, "entries", lambda p: (_ for _ in ()).throw(PermissionError("denied")))
    assert cli("press", "--all") == 0
    cap = capsys.readouterr()
    assert "## Locked" in cap.out and "denied" in cap.err


def test_outcome_without_after_read_still_loads():
    st = Step("a", "x", Phase.FREEZE, Tier.API, "T")
    d = outcome_to_json(Outcome([Result(st, Status.LOCKED)], {}, 1.0))
    del d["results"][0]["step"]["after_read"]
    assert outcome_from_json(d).results[0].step.after_read is False


def test_removed_still_prints_an_earlier_press_after_a_re_press(armed, patch_watch, monkeypatch, capsys):
    fake.snapshot = lambda a: {} if "mail/purge" in fake.ran else {"filters": ["evil"]}
    first = time.time() - 7200
    press_at(monkeypatch, first)
    cli("press", "--user", "mail")
    press_at(monkeypatch, time.time() - 3600)
    cli("press", "--user", "mail")
    capsys.readouterr()
    assert cli("removed", "--user", "mail") == 0
    out = capsys.readouterr().out
    assert f"press of {time.strftime('%Y-%m-%dT%H:%MZ', time.gmtime(first))}" in out
    assert out.count("filters: evil") == 2 and out.count("press of") == 1
    assert cli("removed", "--user", "bank") == 1


def _watch_removes_a_secret_filter(armed, patch_watch):
    """Press one Workspace user, then a watch pass deletes a filter the attacker added afterwards."""
    ws = _ws_armed(armed)
    ws.steps = [Step("", "filters", Phase.PURGE, Tier.API, "Filters", watch=WatchPolicy.REAPPLY)]
    conns = {"fake": fake, "google_workspace": ws}
    cli("press", "--user", "w@d.com", connectors=conns)
    results, live, accounts, baselines, _, logfn = patch_watch.call_args.args
    ws.state["w@d.com/filters"] = False
    ws.snapshot = lambda a: {"filters": []} if ws.state["w@d.com/filters"] else {"filters": ["from:x subject:secret"]}
    executor.watch_once(results, live, accounts, baselines, set(), logfn)
    return conns


def test_watch_removals_are_withheld_from_the_log_and_printed_by_removed(armed, patch_watch, capsys):
    conns = _watch_removes_a_secret_filter(armed, patch_watch)
    text = log_path.read_text()
    assert "secret" not in text and "filters: 1 not in baseline (contents withheld)" in text
    capsys.readouterr()
    assert cli("removed", "--user", "w@d.com", connectors=conns) == 0
    assert "Removed by the watch:\n  - filters: from:x subject:secret\n" in capsys.readouterr().out


def test_watch_removals_still_logged_when_the_vault_cannot_be_written(armed, patch_watch, monkeypatch):
    real = vault.save
    def save(path, data, *a):
        if "watch_removed" in data: raise OSError("disk full")
        real(path, data, *a)
    monkeypatch.setattr(vault, "save", save)
    _watch_removes_a_secret_filter(armed, patch_watch)
    last = log.entries(log_path)[-1]
    assert last["event"] == "reapplied" and "disk full" in last["detail"] and "secret" not in json.dumps(last)
    assert last["removed"] == ["filters: 1 not in baseline (contents withheld)"]


def test_report_lists_what_the_watch_put_back(armed, patch_watch, capsys):
    fake.steps.append(Step("", "fwd", Phase.FREEZE, Tier.API, "Turn off forwarding", watch=WatchPolicy.REAPPLY))
    cli("press", "--user", "mail")
    results, live, accounts, baselines, _, logfn = patch_watch.call_args.args
    fake.snapshot = lambda a: {} if fake.state["mail/fwd"] else {"forwarding": ["on -> thief@x"]}
    for _ in range(2):  # the attacker turns it back on twice
        fake.state["mail/fwd"] = False
        executor.watch_once(results, live, accounts, baselines, set(), logfn)
    capsys.readouterr()
    assert cli("report") == 0
    out = capsys.readouterr().out
    assert out.index("## Removed by this press") < out.index("## Put back during the watch")
    section = out.split("## Put back during the watch")[1]
    assert "- `mail`: Turn off forwarding put back 2 times, last " in section
    assert section.count("  - `forwarding: on -> thief@x`") == 1


def test_two_vault_writers_lose_no_change(armed):
    import threading
    from types import SimpleNamespace
    from panic.session import Session
    with patch("getpass.getpass", return_value=PW):
        sessions = [Session(SimpleNamespace(vault=str(vpath), keyfile=str(kpath))) for _ in range(2)]
    def writer(n):
        for k in range(8):
            sessions[n].update(lambda d: d.__setitem__(f"w{n}-{k}", True))
    ts = [threading.Thread(target=writer, args=(n,)) for n in (0, 1)]
    for t in ts: t.start()
    for t in ts: t.join()
    d = open_vault()
    assert all(d.get(f"w{n}-{k}") for n in (0, 1) for k in range(8))
    assert stat.S_IMODE(Path(f"{vpath}.lock").stat().st_mode) == 0o600


def test_first_creation_refuses_when_a_vault_appeared_meanwhile(bare, capsys):
    def whoami(token):  # another command creates the vault while this one waits for sign-in
        vpath.parent.mkdir()
        vpath.write_bytes(b"other")
        return "me@example.com"
    rc, _ = arm_personal(answers=["y", "y"], whoami=whoami)
    assert rc == 1 and vpath.read_bytes() == b"other" and "appeared" in capsys.readouterr().err


def test_signed_in_mismatch_names_both_addresses_and_the_gmail_variant_rule(bare, capsys):
    rc, _ = arm_personal(answers=["y", "y"], whoami=lambda token: "m.e@googlemail.com")
    err = capsys.readouterr().err
    assert rc == 1 and "m.e@googlemail.com" in err and "me@example.com" in err
    assert ("Gmail treats dotted and googlemail.com variants as the same mailbox, but they must be typed here "
            "exactly as Google shows the primary address.") in err


# -- guard ---------------------------------------------------------------

HIDE = "A mail rule hides or deletes incoming mail."


def trigger(*accounts, items=("rule-json",)):
    fake.signals = lambda acct, snap, base: [
        Finding(acct.id, "rule_hides_mail", Severity.TRIGGER, HIDE, tuple(items)) for _ in [0] if acct.id in accounts]


class Guard:
    def __init__(self):
        self.sleeps, self.notes = [], []

    def run(self, *args, **kw):
        return cli("guard", "--wait", "0", *args, answers=["y"] * 9, sleep=self.sleeps.append,
                   notifier=lambda t, x: self.notes.append((t, x)), **kw)


@pytest.fixture
def guard(armed):
    fake.steps = _steps() + [Step("", "forward", Phase.PURGE, Tier.GUIDED, "Check forwarding"),
                             Step("", "rules", Phase.FREEZE, Tier.API, "Rules", watch=WatchPolicy.REAPPLY)]
    return Guard()


def test_guard_presses_unattended_and_records_why(guard):
    trigger("mail")
    assert guard.run("--passes", "1") == 0
    o = open_vault()["outcomes"][-1]
    assert o["triggers"] and o["triggers"][0].startswith("rule_hides_mail: ")
    guided = [r for r in o["results"] if r["step"]["tier"] == "guided"]
    assert guided and all(r["status"] == "needs_you" for r in guided)  # input was never asked
    assert "## What triggered this press" in latest_report().read_text()
    assert guard.notes[0][0] == "panic: mail"


def test_guard_presses_once_across_passes_and_restarts(guard):
    trigger("mail")
    assert guard.run("--passes", "2") == 0 and len(guard.sleeps) == 1
    assert len(open_vault()["outcomes"]) == 1
    assert guard.run("--passes", "1") == 0  # a new Session: the cooldown survived in the vault
    assert len(open_vault()["outcomes"]) == 1


def test_alert_mode_notifies_and_saves_state_but_never_presses(guard):
    trigger("mail")
    assert guard.run("--on-detect", "alert", "--passes", "1") == 0
    assert "outcomes" not in open_vault() and fake.ran == [] and len(guard.notes) == 1
    assert open_vault()["guard"]["seen"]
    guard.run("--on-detect", "alert", "--passes", "1")
    assert len(guard.notes) == 1  # a restart does not repeat the notice


def test_contain_runs_only_reapply_steps(guard):
    fake.steps += [Step("", a, Phase.FREEZE, Tier.API, a, watch=WatchPolicy.REAPPLY)
                   for a in ("suspend", "disable", "deactivate", "delegates")]
    trigger("mail")
    guard.run("--on-detect", "contain", "--passes", "1")
    assert sorted(fake.ran) == ["bank/rules", "mail/rules"]


def test_contain_with_nothing_to_contain_writes_nothing(guard, capsys):
    fake.steps = [Step("", "suspend", Phase.FREEZE, Tier.API, "Suspend", watch=WatchPolicy.REAPPLY)]
    trigger("mail")
    guard.run("--on-detect", "contain", "--passes", "1")
    assert fake.ran == [] and "outcomes" not in open_vault() and reports() == []
    assert "nothing to contain" in capsys.readouterr().out
    assert "will try to contain" in guard.notes[0][1] and "Containing now" not in guard.notes[0][1]


def test_an_old_vault_keeps_its_released_accounts_unguarded(guard):
    d = open_vault()
    d["released"] = ["mail"]
    vault.save(vpath, d, PW, kpath.read_bytes())
    trigger("mail")
    guard.run("--passes", "1")
    assert "outcomes" not in open_vault() and guard.notes == []
    fake.signals = lambda acct, snap, base: []
    cli("rehearse", answers=["y"])  # mail is offered for resuming
    assert open_vault()["unguarded"] == []


def test_dry_run_changes_nothing(guard):
    trigger("mail")
    before = open_vault()["version"]
    assert guard.run("--dry-run", "--passes", "1") == 0
    assert open_vault()["version"] == before and fake.ran == [] and guard.notes == []


def test_interval_under_30_is_one_line_error(guard, capsys):
    assert guard.run("--interval", "5", "--passes", "1") == 1
    assert capsys.readouterr().err.count("\n") == 1


def test_trigger_downstream_of_another_account_names_resetters_and_spares_them(guard, capsys):
    trigger("bank")
    guard.run("--passes", "1")
    assert "Also check: mail" in capsys.readouterr().out and "Also check: mail" in guard.notes[0][1]
    assert fake.ran and not any(k.startswith("mail/") for k in fake.ran)


def test_org_provider_items_never_leave_the_finding(armed, capsys):
    key = kpath.read_bytes()
    d = open_vault()
    d["accounts"] = [{"id": "staff", "provider": "google_workspace", "protected": False}]
    d["baselines"], d["edges"] = {"staff": {}}, []
    vault.save(vpath, d, PW, key)
    secret = "SECRET-FILTER-CONTENT"
    trigger("staff", items=(secret,))
    g = Guard()
    assert g.run("--passes", "1", connectors={"google_workspace": fake}) == 0
    out = capsys.readouterr()
    everything = out.out + out.err + log_path.read_text() + latest_report().read_text() + repr(g.notes)
    assert secret not in everything and HIDE in log_path.read_text()


def test_personal_items_are_shown_in_the_notification(guard):
    trigger("mail")
    guard.run("--on-detect", "alert", "--passes", "1")
    assert "rule-json" in guard.notes[0][1]


def test_a_second_guard_is_refused(guard, capsys):
    import fcntl
    fd = os.open(f"{vpath}.guard.lock", os.O_RDWR | os.O_CREAT)
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        assert guard.run("--passes", "1") == 1
    finally:
        os.close(fd)
    assert "A guard is already running for this vault." in capsys.readouterr().err


def test_a_failed_automatic_press_does_not_kill_the_guard(guard, monkeypatch, capsys):
    trigger("mail")
    monkeypatch.setattr(executor, "press", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("kaboom")))
    assert guard.run("--passes", "2") == 0
    out = capsys.readouterr().out
    assert "automatic press failed for mail" in out and "kaboom" in out and "panic press" in out
    assert any(e["event"] == "guard_notice" and "kaboom" in e["detail"] for e in log.entries(log_path))
    assert "pressed" in open_vault()["guard"] and open_vault()["guard"]["pressed"]["mail"]
    assert any("automatic press failed for mail" in n[1] for n in guard.notes)
    assert "mail: the automatic press failed; run `panic press` by hand" in out
    assert "already handling" not in out


def test_trigger_notification_says_the_guard_is_pressing(guard):
    trigger("mail")
    guard.run("--passes", "1")
    assert "Pressing now." in guard.notes[0][1]


def test_an_old_vault_guard_state_loads(armed):
    d = open_vault()
    d["guard"] = {"seen": ["mail|rule_hides_mail|rule-json"], "cursors": {}, "pressed": {}}
    vault.save(vpath, d, PW, kpath.read_bytes())
    trigger("bank")
    g = Guard()
    assert g.run("--on-detect", "alert", "--passes", "1") == 0
    state = open_vault()["guard"]
    assert isinstance(state["seen"], dict) and state["events_seen"] == {} and "unguarded" not in open_vault()
    assert [n[0] for n in g.notes] == ["panic: bank"]


def test_release_leaves_the_account_unguarded_until_rehearse_resumes_it(armed):
    fake.release = lambda a: "pw"
    cli("release", "--user", "mail", answers=["y"])
    assert open_vault()["unguarded"] == ["mail"]
    fake.snap = {"filters": ["x"]}
    cli("rehearse", answers=["y", "n", "n"])  # approve mail, decline resuming it, decline bank
    assert open_vault()["unguarded"] == ["mail"] and open_vault()["released"] == ["mail"]
    fake.snap = {}
    cli("rehearse", answers=["y"])  # mail now matches its baseline and is still offered
    assert open_vault()["unguarded"] == [] and open_vault()["released"] == ["mail"]


def test_released_then_resumed_is_not_relocked_until_a_new_guard_press(guard):
    fake.steps.append(Step("", "suspend", Phase.FREEZE, Tier.API, "Suspend", watch=WatchPolicy.REAPPLY))
    fake.release = lambda a: fake.state.__setitem__("mail/suspend", False) or "pw"
    trigger("mail")
    guard.run("--passes", "1")
    assert fake.state["mail/suspend"] is True
    cli("release", "--user", "mail", answers=["y"])
    fake.signals = lambda acct, snap, base: []
    cli("rehearse", answers=["y"])
    fake.ran.clear()
    guard.run("--passes", "1")  # inside the window: the watch leaves the released lock alone
    assert "mail/suspend" not in fake.ran and fake.state["mail/suspend"] is False
    d = open_vault()
    d["guard"]["pressed"] = {k: v - 25 * 3600 for k, v in d["guard"]["pressed"].items()}
    vault.save(vpath, d, PW, kpath.read_bytes())
    trigger("mail")
    guard.run("--passes", "1")  # a new automatic press clears released
    assert "mail" not in open_vault()["released"] and fake.state["mail/suspend"] is True
    fake.state["mail/suspend"] = False
    fake.signals = lambda acct, snap, base: []
    guard.run("--passes", "1")
    assert fake.state["mail/suspend"] is True  # and the watch holds the new lock


def _lock_step(provider):
    from panic.google_workspace import Workspace
    from panic.microsoft_365 import Microsoft365
    from panic.slack import Slack
    conn = {"google_workspace": lambda: Workspace({}, "admin@d.com", "d.com"),
            "microsoft_365": lambda: Microsoft365({"admin": "admin@d.com"}, api=object(), token=lambda: ""),
            "slack": lambda: Slack({"token": "t", "plan": "business"}, object(), object(), object())}[provider]()
    acct = Account("a", provider)
    return next(s for s in conn.catalog(acct) if s.tier is Tier.API and s.phase is Phase.FREEZE
                and s.watch is WatchPolicy.REAPPLY)


@pytest.mark.parametrize("provider", ["google_workspace", "microsoft_365", "slack"])
def test_release_then_watch_never_relocks(armed, patch_watch, provider):
    lock = replace(_lock_step(provider), account="")
    org = FakeConnector(provider=provider, steps=[lock])
    org.release = lambda acct: org.state.__setitem__(f"{acct.id}/{lock.action}", False) or "pw"
    d = open_vault()
    d["accounts"].append({"id": "staff", "provider": provider, "protected": False})
    d["baselines"]["staff"] = {}
    vault.save(vpath, d, PW, kpath.read_bytes())
    conns = {provider: org}
    assert cli("press", "--user", "staff", connectors=conns) == 0
    assert cli("release", "--user", "staff", answers=["y"], connectors=conns) == 0
    d = open_vault()
    results = [r for o in d["outcomes"] for r in outcome_from_json(o).results]
    accounts = [Account(**x) for x in d["accounts"]]
    assert executor.watch_once(results, conns, accounts, d["baselines"], set(d["released"]), lambda e: None) == []
    assert org.ran == [f"staff/{lock.action}"]


def test_a_failed_pass_is_reported_and_the_guard_carries_on(guard, monkeypatch, capsys):
    trigger("mail")
    real, calls = vault.save, []

    def flaky(*a, **k):
        calls.append(1)
        if len(calls) == 1:
            raise OSError("disk full")
        return real(*a, **k)

    monkeypatch.setattr("panic.vault.save", flaky)
    assert guard.run("--passes", "2") == 0
    assert "OSError: disk full" in capsys.readouterr().out and any("still running" in n[1] for n in guard.notes)
    assert any(e.get("code") == "pass_failed" for e in log.entries(log_path))
    assert len(open_vault()["outcomes"]) == 1  # the next pass pressed once
