"""One polling pass of the self-detection guard. Pure: reading, acting, notifying and saving are arguments."""
import time
from datetime import datetime, timezone
from typing import Callable

from panic.graph import downstream
from panic.model import Account, Edges, Finding, Severity, Snapshot
from panic.signals import TEXT

COOLDOWN_S = 24 * 3600


def new_state() -> dict:
    return {"seen": [], "cursors": {}, "pressed": {}}


def _notice(account: str, code: str) -> Finding:
    return Finding(account, code, Severity.NOTICE, TEXT[code])


def _key(f: Finding) -> str:
    return f"{f.account}|{f.code}|{'|'.join(f.items)}"


def _read(conn, account: Account, baseline: Snapshot | None) -> list[Finding]:
    snap = conn.snapshot(account)
    if baseline is None:
        raise KeyError(f"no baseline recorded for {account.id}")
    return conn.signals(account, snap, baseline)


def guard_once(accounts: list[Account], edges: Edges, connectors: dict, baselines: dict[str, Snapshot],
               released: set[str], state: dict, mode: str,
               act: Callable[[list[str], list[Finding]], None], notify: Callable[[Finding], None],
               save: Callable[[], None], now: Callable[[], float] = time.time,
               dry_run: bool = False) -> list[str]:
    lines: list[str] = []
    armed = {a.id: a for a in accounts}
    read = found = 0
    verb = "would " if dry_run else ""

    def report(f: Finding) -> None:
        lines.append(f"{verb}notify {f.account}: {f.text}")
        if not dry_run:
            notify(f)

    for acct in accounts:
        conn = connectors.get(acct.id)
        has_signals = getattr(conn, "signals", None) is not None
        has_events = getattr(conn, "events", None) is not None
        if acct.protected or acct.id in released or not (has_signals or has_events):
            continue
        read += 1
        notices: list[Finding] = []
        triggers: list[Finding] = []
        event_triggers: list[Finding] = []
        try:
            snap_found = _read(conn, acct, baselines.get(acct.id)) if has_signals else []
        except Exception:  # includes the fail-closed missing baseline
            found += 1
            _handle_notice(_notice(acct.id, "unreadable"), state, dry_run, report)
            continue
        if has_events:
            t0 = now()  # taken before the call so entries logged during it fall in the next window
            since = state["cursors"].get(acct.id, t0)
            try:
                ev = conn.events(acct, since)
                if not dry_run:
                    state["cursors"][acct.id] = t0
            except Exception:  # the window stays unread: the cursor does not move
                ev = [_notice(acct.id, "events_unreadable")]
            event_triggers = [f for f in ev if f.severity == Severity.TRIGGER]
            notices += [f for f in ev if f.severity == Severity.NOTICE]
        notices += [f for f in snap_found if f.severity == Severity.NOTICE]
        triggers = [f for f in snap_found if f.severity == Severity.TRIGGER]
        found += len(snap_found) + len(ev if has_events else [])
        for f in notices:
            _handle_notice(f, state, dry_run, report)

        if triggers:
            try:
                again = {f.code for f in _read(conn, acct, baselines.get(acct.id)) if f.severity == Severity.TRIGGER}
                triggers = [f for f in triggers if f.code in again]
            except Exception:  # a failed re-read confirms nothing; the next pass re-evaluates
                triggers = []
                found += 1
                _handle_notice(_notice(acct.id, "unreadable"), state, dry_run, report)
        triggers += event_triggers
        if not triggers:
            continue
        pressed = state["pressed"].get(acct.id)
        in_cooldown = pressed is not None and pressed > now() - COOLDOWN_S
        acting = mode != "alert" and not in_cooldown
        for f in triggers:
            key = _key(f)
            fresh = key not in state["seen"]
            if fresh and not dry_run:
                state["seen"].append(key)
            if fresh or acting:
                report(f)
            else:  # persistent finding: same line, no repeat notification
                lines.append(f"notify {f.account}: {f.text}")
        if mode == "alert":
            continue
        if in_cooldown:
            lines.append(f"{acct.id}: the watch is already handling this")
            continue
        targets = [t for t in downstream(acct.id, edges)
                   if t in armed and not armed[t].protected and t not in released]
        lines.append(f"{verb}press {', '.join(targets)}")
        if dry_run:
            continue
        for t in targets:
            state["pressed"][t] = now()
        save()
        act(targets, triggers)

    stamp = datetime.fromtimestamp(now(), timezone.utc).strftime("%H:%M:%S")
    lines.append(f"{stamp} read {read} accounts, {found} findings")
    return lines


def _handle_notice(f: Finding, state: dict, dry_run: bool, report: Callable[[Finding], None]) -> None:
    key = _key(f)
    if key in state["seen"]:
        return
    if not dry_run:
        state["seen"].append(key)
    report(f)
