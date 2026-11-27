"""One polling pass of the self-detection guard. Pure: reading, acting, notifying and saving are arguments."""
import time
from datetime import datetime, timezone
from typing import Callable

from panic.graph import downstream, resetters
from panic.model import Account, Edges, Finding, Severity, Snapshot
from panic.signals import TEXT

COOLDOWN_S = 24 * 3600
RENOTIFY_S = 3600  # an account that stays unreadable is notified again this often
EVENT_OVERLAP_S = 7200  # provider logs index late: every read goes back this far before the cursor
EVENTS_KEPT_S = 48 * 3600


def new_state() -> dict:
    # seen and events_seen: key -> when it was last notified or read.
    return {"seen": {}, "cursors": {}, "pressed": {}, "events_seen": {}, "failed": [], "asks": {}}


def load_state(raw: dict | None) -> dict:
    """The saved guard state; keys an older vault lacks start empty."""
    state = {**new_state(), **(raw or {})}
    if isinstance(state["seen"], list):  # older vaults kept a list of keys
        state["seen"] = dict.fromkeys(state["seen"], 0.0)
    return state


def _notice(account: str, code: str) -> Finding:
    return Finding(account, code, Severity.NOTICE, TEXT[code])


def _key(f: Finding) -> str:
    return f"{f.account}|{f.code}|{'|'.join(f.items)}"


def _read(conn, account: Account, baseline: Snapshot | None) -> tuple[Snapshot, list[Finding]]:
    snap = conn.snapshot(account)
    if baseline is None:
        raise KeyError(f"no baseline recorded for {account.id}")
    return snap, conn.signals(account, snap, baseline)


def guard_once(accounts: list[Account], edges: Edges, connectors: dict, baselines: dict[str, Snapshot],
               released: set[str], state: dict, mode: str,
               act: Callable[[list[str], list[Finding]], bool | None], notify: Callable[[Finding, str], None],
               save: Callable[[], None], now: Callable[[], float] = time.time,
               dry_run: bool = False, wait: float = 0, ask: Callable[[str, list[Finding], float], None] | None = None,
               accept: Callable[[str, Snapshot], None] | None = None) -> list[str]:
    """`released` holds the accounts the guard must skip; `act` returns False when the press failed.
    With `wait` > 0 in press or contain mode, each finding is asked about first (`ask`); the answers
    land in state["asks"]. A lock answer or an unanswered risky question at its deadline acts; harmless
    changes the user accepted, or left unanswered past the deadline, become the baseline (`accept`)."""
    lines: list[str] = []
    armed = {a.id: a for a in accounts}
    read = found = skipped = 0
    verb = "would " if dry_run else ""
    t = now()
    seen, events_seen, asks = state["seen"], state["events_seen"], state["asks"]
    asking = wait > 0 and mode != "alert"
    if not dry_run:
        for k in [k for k, at in events_seen.items() if at < t - EVENTS_KEPT_S]:
            del events_seen[k]

    def cooling(i: str) -> bool:
        pressed = state["pressed"].get(i)
        return pressed is not None and pressed > t - COOLDOWN_S

    def report(f: Finding, notified: bool, extra: str = "") -> None:
        also = ""
        if f.severity is Severity.TRIGGER:
            ids = sorted(resetters(f.account, edges))
            also = f" Also check: {', '.join(ids)}" if ids else ""
        lines.append(f"{verb}notify {f.account}: {f.text}{also}" if notified else f"{f.account}: {f.text}{also}")
        if notified and not dry_run:
            notify(f, also + extra)

    def mark(f: Finding) -> None:
        if not dry_run:
            seen[_key(f)] = t

    def once(f: Finding) -> None:
        if _key(f) not in seen:
            mark(f)
            report(f, True)

    def read_failure(f: Finding) -> None:  # printed every pass, notified again while it lasts
        last = seen.get(_key(f))
        due = last is None or t - last > RENOTIFY_S
        if due:
            mark(f)
        report(f, due)

    def forget(f: Finding) -> None:
        if not dry_run:
            seen.pop(_key(f), None)

    def handle(acct: Account, triggers: list[Finding]) -> None:
        in_cooldown = cooling(acct.id)
        failed = acct.id in state["failed"]
        if mode == "alert":
            doing = " Alert only: nothing is being changed."
        elif in_cooldown:
            doing = (" The automatic press failed: run `panic press` by hand." if failed
                     else " The watch is already handling this.")
        else:
            doing = (" Pressing now." if mode == "press"
                     else " The guard will try to contain it: remove what was added, never lock an account.")
        acting = mode != "alert" and not in_cooldown
        for f in triggers:
            fresh = _key(f) not in seen
            if fresh:
                mark(f)
            report(f, fresh or acting, doing)
        if mode == "alert":
            return
        if in_cooldown:
            lines.append(f"{acct.id}: the automatic press failed; run `panic press` by hand" if failed
                         else f"{acct.id}: the watch is already handling this")
            return
        # A downstream account pressed less than a day ago is left to the watch.
        targets = [x for x in downstream(acct.id, edges)
                   if x in armed and not armed[x].protected and x not in released and (x == acct.id or not cooling(x))]
        lines.append(f"{verb}{'press' if mode == 'press' else 'contain'} {', '.join(targets)}")
        if dry_run:
            return
        for x in targets:
            state["pressed"][x] = t
        save()
        ok = act(targets, triggers) is not False
        state["failed"] = sorted(set(state["failed"]) - set(targets) if ok else set(state["failed"]) | set(targets))


    def ask_pass(acct: Account, conn, snap_found: list[Finding], triggers: list[Finding], ev: list[Finding]) -> None:
        mine = {k: v for k, v in asks.items() if v["account"] == acct.id}
        in_read = {_key(f) for f in snap_found}
        for k, v in mine.items():  # gone from a full read, or an event answered / harmless and out of time
            if (not v["event"] and k not in in_read) or (v["event"] and (
                    v["answer"] == "accept" or (not v["risky"] and t >= v["deadline"]))):
                del asks[k]
        mine = {k: v for k, v in mine.items() if k in asks}
        current = [f for f in snap_found if f.severity == Severity.NOTICE] + triggers + [
            f for f in ev if f.severity == Severity.NOTICE]
        fresh = [f for f in current if _key(f) not in asks]
        for f in fresh:
            asks[_key(f)] = mine[_key(f)] = {"account": acct.id, "risky": f.severity == Severity.TRIGGER,
                                              "event": f in ev, "deadline": t + wait, "answer": None}
        if fresh and ask is not None:
            ask(acct.id, fresh, t + wait)
        if any(v["answer"] == "lock" or (v["risky"] and v["answer"] is None and t >= v["deadline"])
               for v in mine.values()):
            by_key = {_key(f): f for f in current}
            risky = [by_key.get(k) or Finding(acct.id, k.split("|")[1], Severity.TRIGGER, TEXT.get(k.split("|")[1], k))
                     for k, v in mine.items() if v["risky"]]
            for k in mine:
                del asks[k]
            handle(acct, risky)
            return
        keep = {k for k, v in mine.items() if not v["event"] and (
            v["answer"] == "accept" or (not v["risky"] and v["answer"] is None and t >= v["deadline"]))}
        if keep and keep == {k for k, v in mine.items() if not v["event"]}:
            snap, again = _read(conn, acct, baselines.get(acct.id))
            if {_key(f) for f in again} <= keep:
                if accept is not None:
                    accept(acct.id, snap)
                baselines[acct.id] = snap
                for k in keep:
                    del asks[k]

    for acct in accounts:
        conn = connectors.get(acct.id)
        has_signals = getattr(conn, "signals", None) is not None
        has_events = getattr(conn, "events", None) is not None
        if acct.protected or acct.id in released or not (has_signals or has_events):
            skipped += 1
            continue
        read += 1
        try:
            snap, snap_found = _read(conn, acct, baselines.get(acct.id)) if has_signals else (None, [])
        except Exception:  # includes the fail-closed missing baseline
            found += 1
            read_failure(_notice(acct.id, "unreadable"))
            continue
        forget(_notice(acct.id, "unreadable"))
        ev: list[Finding] = []
        events_ok = True
        if has_events:
            cursor = state["cursors"].get(acct.id)
            since = (t if cursor is None else cursor) - EVENT_OVERLAP_S
            try:
                # Per account: one provider entry can name several members.
                ev = [f for f in conn.events(acct, since) if not f.key or f"{f.account}|{f.key}" not in events_seen]
                if not dry_run:
                    state["cursors"][acct.id] = t
                    events_seen.update({f"{f.account}|{f.key}": t for f in ev if f.key})
                forget(_notice(acct.id, "events_unreadable"))
            except Exception:  # the window stays unread: the cursor does not move
                events_ok = False
                found += 1
                read_failure(_notice(acct.id, "events_unreadable"))
        found += len(snap_found) + len(ev)
        if events_ok and not dry_run:  # a finding gone from a full read notifies again if it comes back
            current = {_key(f) for f in snap_found + ev}
            failures = {_key(_notice(acct.id, c)) for c in ("unreadable", "events_unreadable")}
            for k in [k for k in seen if k.startswith(f"{acct.id}|") and k not in current | failures]:
                del seen[k]
        for f in snap_found + ev:
            if f.severity == Severity.NOTICE and not asking:
                once(f)

        triggers = [f for f in snap_found if f.severity == Severity.TRIGGER]
        if triggers:
            try:
                again = {f.code for f in _read(conn, acct, baselines.get(acct.id))[1] if f.severity == Severity.TRIGGER}
                triggers = [f for f in triggers if f.code in again]
            except Exception:  # a failed re-read confirms nothing; the next pass re-evaluates
                triggers = []
                found += 1
                read_failure(_notice(acct.id, "unreadable"))
        triggers += [f for f in ev if f.severity == Severity.TRIGGER]
        if asking:
            if dry_run:
                lines += [f"would ask {acct.id}: {f.text}" for f in snap_found + ev]
            else:
                ask_pass(acct, conn, snap_found, triggers, ev)
            continue
        if triggers:
            handle(acct, triggers)

    stamp = datetime.fromtimestamp(t, timezone.utc).strftime("%H:%M:%S")
    lines.append(f"{stamp} read {read} accounts, {found} findings, {skipped} skipped")
    return lines
