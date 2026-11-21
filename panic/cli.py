"""The `panic` command line: wires the vault, connectors, engine and report together."""
import argparse
import json
import os
import shutil
import sys
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from panic import executor, google_personal, log, notify, report
from panic.cli_arm import _plan_lines, cmd_arm, cmd_rehearse
from panic.cli_guard import cmd_guard
from panic.graph import lock_order, resetters
from panic.model import Outcome, Step
from panic.session import (WATCH_HOURS, CliError, Session, _connectors, _last_outcome, _outcomes, _private_write,
                           _recent_results, _record_outcome, _redact, _reload, _same_device, _unprotected, _warn, _yes,
                           outcome_from_json, outcome_to_json)
from panic.vault import VaultError

DEFAULT_VAULT = "~/.panic/panic.vault"
STALE_DAYS = 30


class _Parser(argparse.ArgumentParser):
    def error(self, message):  # one line, exit code 1
        print(f"error: {message}", file=sys.stderr)
        raise SystemExit(1)


def _guard(what: str, fn) -> None:
    """Run one post-press step; a failure is one warning and never hides the report."""
    try:
        fn()
    except (Exception, KeyboardInterrupt) as e:
        _warn(f"Warning: could not {what}: {str(e) or type(e).__name__}")


# -- map ----------------------------------------------------------------

def cmd_map(a) -> int:
    s = Session(a)
    back = [(y, x) for x, y in s.edges]  # reversed, so "resetters" walks forward
    for acct in s.accounts:
        reach = sorted(resetters(acct.id, back))
        print(f"{acct.id}{' (protected)' if acct.protected else ''}: can reset " + (", ".join(reach) or "nothing"))
    ids = _unprotected(s)
    if ids:
        print(f"Can reset the most: {lock_order(ids, s.edges)[0]}")
    return 0


# -- press / watch / report ---------------------------------------------

def _report_path(s: Session, o: Outcome, ext: str) -> Path:
    # Named by press start, so a later press never overwrites an earlier one's record.
    return Path(f"{s.path}.report-{datetime.fromtimestamp(o.started_at, timezone.utc):%Y%m%dT%H%M%SZ}.{ext}")


def _render(s: Session, outcome: Outcome) -> tuple[str, dict]:
    shown = replace(outcome, touched=_redact(outcome.touched, s.accounts), removed=_redact(outcome.removed, s.accounts))
    try:
        events = log.entries(s.log_path)
    except OSError as e:  # the report must still be shown
        _warn(f"Warning: could not read the audit log: {e}")
        events = []
    return report.render(shown, time.time(), events)


def _write_report(s: Session, outcome: Outcome, md: str, data: dict) -> None:
    _private_write(_report_path(s, outcome, "md"), md.encode())
    _private_write(_report_path(s, outcome, "json"), json.dumps(data, indent=2).encode())


def _publish_report(s: Session, outcome: Outcome) -> None:
    md, data = _render(s, outcome)
    _guard("write the report files", lambda: _write_report(s, outcome, md, data))
    print(md)


def _save_outcome(s: Session, outcome: Outcome) -> None:
    def change(d: dict) -> None:
        _record_outcome(d, outcome)
        d["log_head"] = log.head(s.log_path)

    s.update(change)


def _confirm(step: Step) -> bool:
    print(f"\n{step.account}: {step.title}" + (f"\n  {step.link}" if step.link else ""))
    return _yes("Done?")


def _watch(a, s: Session, outcomes: list[Outcome], conns: dict) -> int:
    now = time.time()
    hours = WATCH_HOURS - (now - outcomes[-1].started_at) / 3600
    if hours <= 0:
        print("The 24-hour watch window has ended.")
        return 0
    results = _recent_results(outcomes, now)
    baselines, last = dict(s.data["baselines"]), s.data

    def reload() -> set[str]:
        nonlocal last
        last = _reload(a, s, conns, last)
        # Refreshed in place, so a reconnected token or an approved baseline applies from the next pass.
        baselines.clear()
        baselines.update(last["baselines"])
        return set(last.get("released", []))

    print(f"Watching for {hours:.1f} more hours. Press Ctrl-C to stop; resume with `panic watch`.")
    try:
        executor.watch(results, conns, s.accounts, baselines, reload, s.log, hours=hours)
    except KeyboardInterrupt:
        print("Watch stopped. Resume with `panic watch`.")
    return 0


def cmd_press(a) -> int:
    if not (a.user or a.all):
        raise CliError("Say who to lock: --user ID (repeatable) or --all.")
    s = Session(a)
    valid = _unprotected(s)
    ids = [u.lower() for u in a.user]
    wrong = [u for u in ids if u not in valid]
    if wrong:
        raise CliError(f"Not a valid target: {', '.join(wrong)}. Valid ids: {', '.join(valid) or 'none'}.")
    targets = set(valid) if a.all else set(ids)
    saved = datetime.fromisoformat(s.data["saved_at"]) if "saved_at" in s.data else None
    if saved and (datetime.now(timezone.utc) - saved).days > STALE_DAYS:
        _warn(f"Warning: this vault copy is over {STALE_DAYS} days old and may be stale; "
              "more may be removed than you expect.")
    conns, accounts = _connectors(a, s.data), s.accounts
    plan = executor.compile_plan([x for x in accounts if x.id in targets], s.edges, conns)
    if a.dry_run:
        out = executor.press(plan, accounts, s.edges, conns, s.data["baselines"], _confirm, lambda e: None, dry_run=True)
        print("Dry run: nothing was changed. The press would run:")
        print("\n".join(_plan_lines(plan)) or "  (no steps)")
        for acct, items in _redact(out.touched, accounts).items():
            if items:
                print(f"{acct}: outside the baseline:")
                print("\n".join(f"  - {i}" for i in items))
        return 0
    if targets & set(s.data.get("released", [])):  # a new press puts suspension enforcement back
        _guard("clear the released list", lambda: s.update(
            lambda d: d.__setitem__("released", sorted(set(d.get("released", [])) - targets))))

    def checkpoint(o: Outcome) -> None:  # survives a process that dies during the walkthrough
        _save_outcome(s, o)
        _write_report(s, o, *_render(s, o))

    # press absorbs Ctrl-C and EOF, so everything below still runs after an interrupt.
    out = executor.press(plan, accounts, s.edges, conns, s.data["baselines"], _confirm, s.log,
                         progress=_warn, checkpoint=checkpoint)
    _guard("save the outcome to the vault", lambda: _save_outcome(s, out))
    _publish_report(s, out)
    return _watch(a, s, [o for o in _outcomes(s) if o.started_at != out.started_at] + [out], conns)


def cmd_watch(a) -> int:
    s = Session(a)
    _last_outcome(s)  # one clear error when nothing was pressed
    return _watch(a, s, _outcomes(s), _connectors(a, s.data))


def cmd_report(a) -> int:
    s = Session(a)
    outcome = _last_outcome(s)
    if not log.verify(s.log_path) or not log.contains(s.log_path, s.data.get("log_head", "")):
        _warn("Warning: the audit log has been changed since the last press.")
    _publish_report(s, outcome)
    own = _report_path(s, outcome, "md")
    earlier = sorted(p.name for p in s.path.parent.glob(f"{s.path.name}.report-*.md") if p != own)
    if earlier:
        print("Earlier reports: " + ", ".join(earlier))
    return 0


def cmd_removed(a) -> int:
    s = Session(a)
    uid = a.user.lower()
    if uid not in _unprotected(s):
        raise CliError(f"Not a valid account: {uid}. Valid ids: {', '.join(_unprotected(s)) or 'none'}.")
    # Every press, newest first: a re-press reads after the first one already removed things.
    shown = [o for o in reversed(_outcomes(s)) if o.removed.get(uid) or o.touched.get(uid)]
    watched = s.data.get("watch_removed", {}).get(uid, [])
    if not shown and not watched:
        raise CliError(f"No press has recorded anything for {uid}.")
    # Unredacted on purpose: this is how an admin hands a user back their own deleted settings.
    for o in shown:
        print(f"{uid}, press of {datetime.fromtimestamp(o.started_at, timezone.utc):%Y-%m-%dT%H:%MZ}")
        for title, items in (("Removed by the press", o.removed.get(uid, [])),
                             ("Attacker may have touched", o.touched.get(uid, []))):
            print(f"{title}:")
            print("\n".join(f"  - {i}" for i in items) or "  Nothing.")
    print("Removed by the watch:")
    print("\n".join(f"  - {i}" for i in watched) or "  Nothing.")
    return 0


# -- release / export ---------------------------------------------------

def cmd_release(a) -> int:
    s = Session(a)
    uid = a.user.lower()
    acct = next((x for x in s.accounts if x.id == uid and not x.protected), None)
    if acct is None:
        raise CliError(f"Not a valid account: {uid}. Valid ids: {', '.join(_unprotected(s)) or 'none'}.")
    conn = _connectors(a, s.data).get(acct.provider)
    if not hasattr(conn, "release"):
        raise CliError(f"{acct.provider} accounts cannot be released by this tool.")
    if not _yes(f"Release {uid}? This unsuspends it and sets a temporary password."):
        print("Nothing changed.")
        return 1
    # Recorded first, so a running watch never re-suspends an account that was just released.
    s.update(lambda d: d.__setitem__("released", sorted({*d.get("released", []), uid})))
    try:
        pw = conn.release(acct)
    except Exception as e:
        s.update(lambda d: d.__setitem__("released", sorted(set(d.get("released", [])) - {uid})))
        raise CliError(f"could not release {uid}: {e}")
    print(f"Released {uid}. Temporary password (shown once): {pw}")
    return 0


def cmd_export(a) -> int:
    s_path, dest = Path(a.vault).expanduser(), Path(a.dest).expanduser()
    k = a.keyfile or os.environ.get("PANIC_KEYFILE")
    if not k or not Path(k).expanduser().exists():
        raise CliError("Give an existing --keyfile (or set PANIC_KEYFILE); it is used to check the copy goes elsewhere.")
    if not s_path.exists():
        raise CliError(f"No vault at {s_path}. Run `panic arm` first.")
    if _same_device(Path(k).expanduser(), dest):
        raise CliError("DEST is on the same device as the key file; a copy there would not protect the vault.")
    shutil.copyfile(s_path, dest)
    os.chmod(dest, 0o600)
    print(f"Vault copied to {dest}.")
    return 0


# -- entry point --------------------------------------------------------

def _parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)  # lets global options follow the command too
    common.add_argument("--vault", default=argparse.SUPPRESS, help=f"vault path (default {DEFAULT_VAULT})")
    common.add_argument("--keyfile", default=argparse.SUPPRESS, help="key file path (or env PANIC_KEYFILE)")
    p = _Parser(prog="panic", description="Lock down connected accounts, root first, and prove it.")
    p.add_argument("--vault", default=DEFAULT_VAULT, help=f"vault path (default {DEFAULT_VAULT})")
    p.add_argument("--keyfile", default=None, help="key file path (or env PANIC_KEYFILE)")
    sub = p.add_subparsers(dest="command", required=True, parser_class=_Parser)

    def add(name, fn, help_):
        sp = sub.add_parser(name, parents=[common], help=help_, description=help_)
        sp.set_defaults(fn=fn)
        return sp

    arm = add("arm", cmd_arm, "Add an account (or a Workspace domain) and record its baseline.")
    arm.add_argument("--personal", metavar="EMAIL")
    arm.add_argument("--client-secrets", metavar="FILE", help="your Google OAuth desktop client file")
    arm.add_argument("--reconnect", action="store_true", help="re-authorise an armed account only")
    arm.add_argument("--workspace", action="store_true")
    arm.add_argument("--sa-key", metavar="FILE", help="Workspace service-account key file")
    arm.add_argument("--admin", metavar="EMAIL", help="protected break-glass admin")
    arm.add_argument("--domain")
    add("map", cmd_map, "Show which accounts can reset which.")
    add("rehearse", cmd_rehearse, "Read every account and show what is outside its baseline.")
    press = add("press", cmd_press, "Lock accounts down, root first, then watch for 24 hours.")
    press.add_argument("--user", action="append", default=[], metavar="ID", help="account to lock (repeatable)")
    press.add_argument("--all", action="store_true", help="every account except protected ones")
    press.add_argument("--dry-run", action="store_true", help="show the plan; change nothing")
    g = add("guard", cmd_guard, "Watch armed accounts and press automatically when one looks taken over.")
    g.add_argument("--interval", type=float, default=300, metavar="SECONDS", help="seconds between passes (min 30)")
    g.add_argument("--on-detect", choices=["press", "contain", "alert"], default="press")
    g.add_argument("--dry-run", action="store_true", help="read and report; notify, press and save nothing")
    g.add_argument("--passes", type=int, default=0, help=argparse.SUPPRESS)
    add("watch", cmd_watch, "Resume the 24-hour watch after a press.")
    rel = add("release", cmd_release, "Unsuspend one account with a temporary password.")
    rel.add_argument("--user", required=True, metavar="ID")
    add("report", cmd_report, "Show the report from the last press at the current time.")
    rem = add("removed", cmd_removed, "Print everything the last press removed from one account, unredacted.")
    rem.add_argument("--user", required=True, metavar="ID")
    exp = add("export", cmd_export, "Copy the vault file to DEST (a second device).")
    exp.add_argument("dest", metavar="DEST")
    return p


def main(argv: list[str] | None = None, connectors: dict | None = None, authorize=None, whoami=None,
         sleep=time.sleep, notifier=notify.notify) -> int:
    try:
        a = _parser().parse_args(argv)
        a.connectors, a.authorize = connectors, authorize or google_personal.authorize
        a.whoami = whoami or google_personal.signed_in_address
        a.sleep, a.notifier = sleep, notifier
        return a.fn(a)
    except SystemExit as e:  # --help, or a usage error already printed
        return int(e.code or 0)
    except (CliError, VaultError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print("Cancelled.", file=sys.stderr)
        return 1
