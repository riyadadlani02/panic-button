"""`panic guard`: poll armed accounts and press automatically when something looks like a takeover."""
import copy
import fcntl
import os
import time
from pathlib import Path

from panic import executor
from panic.graph import resetters
from panic.guard import guard_once, new_state
from panic.model import Account, Finding, Outcome, Severity, Tier, WatchPolicy
from panic.session import (ORG_PROVIDERS, CliError, Session, _connectors, _outcomes, _recent_results, _reload,
                           _warn)
from panic.signals import TEXT

MIN_INTERVAL_S = 30
NOTICE_CODES = {"changed", "unreadable", "events_unreadable"}


def _lock(a) -> int:
    fd = os.open(f"{Path(a.vault).expanduser()}.guard.lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise CliError("A guard is already running for this vault.")
    return fd


def cmd_guard(a) -> int:
    from panic.cli import _guard, _publish_report, _render, _save_outcome, _write_report  # cli imports this module
    if a.interval < MIN_INTERVAL_S:
        raise CliError(f"--interval must be at least {MIN_INTERVAL_S} seconds.")
    fd = _lock(a)  # held until the process ends
    try:
        s = Session(a)
        conns = _connectors(a, s.data)
        data = s.data
        texts = {TEXT[c] for c in NOTICE_CODES}
        passes = 0
        print(f"Guarding every {a.interval:g}s, on detect: {a.on_detect}{' (dry run)' if a.dry_run else ''}. Ctrl-C to stop.")
        while True:
            data = _reload(a, s, conns, data)
            s.data = data
            try:
                accounts = [Account(**x) for x in data["accounts"]]
                edges = [tuple(e) for e in data["edges"]]
                org = {x.id for x in accounts if x.provider in ORG_PROVIDERS}
                state = data.get("guard") or new_state()
                before = copy.deepcopy(state)

                def also(account: str) -> str:
                    ids = sorted(resetters(account, edges))
                    return f" Also check: {', '.join(ids)}" if ids else ""

                def shown(f: Finding) -> str:  # items are raw provider data: personal accounts only
                    return f.text if f.account in org or not f.items else f"{f.text} ({'; '.join(f.items)})"

                def notifier(f: Finding) -> None:
                    trig = f.severity is Severity.TRIGGER
                    s.log({"event": "guard_trigger" if trig else "guard_notice", "account": f.account, "code": f.code,
                           "detail": shown(f)})
                    a.notifier(f"panic: {f.account}", shown(f) + (also(f.account) if trig else ""))

                def save() -> None:
                    s.update(lambda d: d.__setitem__("guard", state))

                def act(targets: list[str], findings: list[Finding]) -> None:
                    def checkpoint(o: Outcome) -> None:  # survives a process that dies mid-press
                        o.triggers = [f"{f.code}: {shown(f)}" for f in findings]
                        _save_outcome(s, o)
                        _write_report(s, o, *_render(s, o))

                    try:
                        plan = executor.compile_plan([x for x in accounts if x.id in targets], edges, conns)
                        if a.on_detect == "contain":
                            plan = [st for st in plan if st.tier is Tier.API and st.watch is WatchPolicy.REAPPLY]
                        out = executor.press(plan, accounts, edges, conns, data["baselines"], lambda step: False, s.log,
                                             progress=_warn, checkpoint=checkpoint)
                        out.triggers = [f"{f.code}: {shown(f)}" for f in findings]
                        _guard("save the outcome to the vault", lambda: _save_outcome(s, out))
                        _publish_report(s, out)
                    except Exception as e:  # the guard outlives a failed press; `pressed` stays set, so no retry loop
                        who = ", ".join(sorted({f.account for f in findings}))
                        msg = f"the automatic press failed for {who}: {e}. Run `panic press` by hand."
                        s.log({"event": "guard_notice", "account": who, "code": "press_failed", "detail": msg})
                        print(f"Guard: {msg}")

                per_acct = {x.id: conns[x.provider] for x in accounts if x.provider in conns}
                for line in guard_once(accounts, edges, per_acct, data["baselines"], set(data.get("released", [])),
                                       state, a.on_detect, act, notifier, save, dry_run=a.dry_run):
                    notified = line.removeprefix("would ").removeprefix("notify ")
                    acct, _, text = notified.partition(": ")
                    trigger_line = line != notified and text not in texts and acct in {x.id for x in accounts}
                    print(line + (also(acct) if trigger_line else ""))
                if not a.dry_run:
                    if state != before:  # guard_once only saves before acting; notices and cursors need it too
                        save()
                    for line in executor.watch_once(_recent_results(_outcomes(s), time.time()), conns, accounts,
                                                    data["baselines"], set(data.get("released", [])), s.log):
                        print(line)
            except Exception as e:  # unattended: a failed pass must not end the protection
                msg = f"a guard pass failed ({type(e).__name__}: {e}); the guard is still running."
                try:
                    s.log({"event": "guard_notice", "account": "-", "code": "pass_failed", "detail": msg})
                except Exception:
                    pass
                a.notifier("panic: guard", msg)
                print(f"Guard: {msg}")
            passes += 1
            if a.passes and passes >= a.passes:
                return 0
            a.sleep(a.interval)
    except KeyboardInterrupt:
        print("Guard stopped.")
        return 0
    finally:
        os.close(fd)
