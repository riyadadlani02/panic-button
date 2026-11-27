"""`panic guard`: poll armed accounts and press automatically when something looks like a takeover."""
import copy
import fcntl
import os
import time
from datetime import datetime
from pathlib import Path

from panic import executor
from panic.guard import _from_ask, _key, guard_once, load_state
from panic.model import Account, Finding, Outcome, Severity, Tier, WatchPolicy
from panic.session import (ORG_PROVIDERS, CliError, Session, _connectors, _outcomes, _recent_results, _reload,
                           _unguarded, _warn)
from panic.signals import adopted

MIN_INTERVAL_S = 30
MAX_WAIT_S = 7 * 24 * 3600
# Contain never locks anyone out, and Workspace's delegates step removes every delegate, baselined or not.
CONTAIN_SKIP = executor.LOCK_ACTIONS | {"delegates"}


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
    if a.wait < 0:
        raise CliError("--wait must be 0 or more seconds.")
    if not a.wait <= MAX_WAIT_S:  # also refuses inf and nan
        raise CliError(f"--wait must be at most {MAX_WAIT_S} seconds (7 days).")
    fd = _lock(a)  # held until the process ends
    try:
        s = Session(a)
        conns = _connectors(a, s.data, s)
        data = s.data
        passes = 0
        dialogs: list[tuple] = []  # (process, keys it answers)
        asked: set[str] = set()
        mark = {"t": 0.0}  # start of the latest pass
        state: dict = {"asks": {}}
        asking = a.wait > 0 and a.on_detect != "alert" and not a.dry_run
        fate_word = "locked" if a.on_detect == "press" else "contained"
        print(f"Guarding every {a.interval:g}s, on detect: {a.on_detect}, wait: {a.wait:g}s"
              f"{' (dry run)' if a.dry_run else ''}. Ctrl-C to stop.")

        def poll() -> bool:  # an answer or a due deadline starts a pass at once
            changed = False
            for d in list(dialogs):
                r = a.asker.answer(d[0])
                if r is None:
                    continue
                dialogs.remove(d)
                for k in d[1] if r in ("accept", "lock") else ():
                    if k in state["asks"]:
                        state["asks"][k]["answer"] = r
                        changed = True
            if changed:
                try:
                    s.update(lambda x: x.__setitem__("guard", state))
                except Exception as e:  # unattended: a failed save must not end the protection
                    msg = f"saving an answer failed ({type(e).__name__}: {e}); the guard is still running."
                    a.notifier("panic: guard", msg)
                    print(f"Guard: {msg}")
                    return False
            # only a deadline that fell due since the last pass began: an overdue one the pass already saw waits
            return changed or any(mark["t"] < v["deadline"] <= time.time() for v in state["asks"].values())

        def pause() -> None:
            if not asking:
                a.sleep(a.interval)
                return
            for _ in range(int(a.interval)):
                a.sleep(1)
                if poll():
                    return
        while True:
            mark["t"] = time.time()
            data = _reload(a, s, conns, data)
            s.data = data
            try:
                accounts = [Account(**x) for x in data["accounts"]]
                edges = [tuple(e) for e in data["edges"]]
                org = {x.id for x in accounts if x.provider in ORG_PROVIDERS}
                state = load_state(data.get("guard"))
                before = copy.deepcopy(state)

                def dialog(acct: str, texts: list[str], risky: bool, keys: list[str], deadline: float) -> None:
                    asked.update(keys)
                    fate = (f"it will be {fate_word} at {datetime.fromtimestamp(deadline):%H:%M}" if risky
                            else f"it will be accepted at {datetime.fromtimestamp(deadline):%H:%M}")
                    proc = a.asker.open_dialog(f"panic: {acct}", "\n".join(texts) + f"\nIf you do not answer, {fate}.",
                                               deadline - time.time())
                    if proc is not None:
                        dialogs.append((proc, set(keys)))

                for k, v in list(state["asks"].items()):  # a reloaded question reopens alone, with the text it showed
                    if k not in asked and v["answer"] is None and v["deadline"] > time.time():
                        dialog(v["account"], [v.get("text") or _from_ask(k, v).text], v["risky"], [k],
                               v["deadline"])

                def asker(acct: str, findings: list[Finding], deadline: float) -> None:
                    risky = any(f.severity is Severity.TRIGGER for f in findings)
                    for f in findings:
                        state["asks"][_key(f)]["text"] = shown(f)
                        s.log({"event": "guard_question", "account": acct, "code": f.code, "detail": shown(f)})
                    fate = (f"It will be {fate_word} at {datetime.fromtimestamp(deadline):%H:%M} unless you answer."
                            if risky else f"It will be accepted at {datetime.fromtimestamp(deadline):%H:%M} unless you answer.")
                    texts = list(dict.fromkeys(shown(f) for f in findings))  # org items share one text
                    a.notifier(f"panic: {acct}", " ".join(texts) + f" {fate} It was me? Run "
                               f"`panic rehearse`. Lock it? Run `panic press --user {acct}`.")
                    dialog(acct, texts, risky, [_key(f) for f in findings], deadline)

                def accepted(acct: str, snap) -> None:
                    s.update(lambda d: d["baselines"].__setitem__(acct, snap))
                    s.log({"event": "guard_accepted", "account": acct})

                def extended(acct: str, cats) -> None:
                    def grow(d: dict) -> None:  # a category another writer saved meanwhile is kept
                        if acct in d["baselines"]:
                            d["baselines"][acct].update(adopted(d["baselines"][acct], cats))
                    s.update(grow)
                    s.log({"event": "baseline_extended", "account": acct, "detail": ", ".join(sorted(cats))})

                def shown(f: Finding) -> str:  # items are raw provider data: personal accounts only
                    return f.text if f.account in org or not f.items else f"{f.text} ({'; '.join(f.items)})"

                def notifier(f: Finding, extra: str) -> None:
                    s.log({"event": "guard_trigger" if f.severity is Severity.TRIGGER else "guard_notice",
                           "account": f.account, "code": f.code, "detail": shown(f)})
                    a.notifier(f"panic: {f.account}", shown(f) + extra)

                def save() -> None:
                    s.update(lambda d: d.__setitem__("guard", state))

                def act(targets: list[str], findings: list[Finding]) -> bool:
                    def checkpoint(o: Outcome) -> None:  # survives a process that dies mid-press
                        o.triggers = [f"{f.code}: {shown(f)}" for f in findings]
                        _save_outcome(s, o)
                        _write_report(s, o, *_render(s, o))

                    try:
                        plan = executor.compile_plan([x for x in accounts if x.id in targets], edges, conns)
                        if a.on_detect == "contain":
                            plan = [st for st in plan if st.tier is Tier.API and st.watch is WatchPolicy.REAPPLY
                                    and st.action not in CONTAIN_SKIP]
                            if not plan:
                                print(f"Guard: nothing to contain for {', '.join(targets)}.")
                                return True
                        else:  # a new press puts lock enforcement back
                            _guard("clear the released list", lambda: s.update(lambda d: d.__setitem__(
                                "released", sorted(set(d.get("released", [])) - set(targets)))))
                        with a.press_lock:
                            out = executor.press(plan, accounts, edges, conns, data["baselines"], lambda step: False,
                                                 s.log, progress=_warn, checkpoint=checkpoint)
                        out.triggers = [f"{f.code}: {shown(f)}" for f in findings]
                        _guard("save the outcome to the vault", lambda: _save_outcome(s, out))
                        _publish_report(s, out)
                        return True
                    except Exception as e:  # the guard outlives a failed press; `pressed` stays set, so no retry loop
                        who = ", ".join(sorted({f.account for f in findings}))
                        msg = f"the automatic press failed for {who}: {e}. Run `panic press` by hand."
                        print(f"Guard: {msg}")
                        _guard("log the failed press", lambda: s.log(
                            {"event": "guard_notice", "account": who, "code": "press_failed", "detail": msg}))
                        a.notifier(f"panic: {who}", msg)
                        return False

                per_acct = {x.id: conns[x.provider] for x in accounts if x.provider in conns}
                for line in guard_once(accounts, edges, per_acct, data["baselines"], set(_unguarded(data)),
                                       state, a.on_detect, act, notifier, save, dry_run=a.dry_run, wait=a.wait,
                                       ask=asker, accept=accepted, extend=extended):
                    print(line)
                if not a.dry_run:
                    if state != before:  # guard_once only saves before acting; notices and cursors need it too
                        save()
                    for line in executor.watch_once(_recent_results(_outcomes(s), time.time()), conns, accounts,
                                                    data["baselines"], set(s.data.get("released", [])), s.log):
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
            pause()
    except KeyboardInterrupt:
        print("Guard stopped.")
        return 0
    finally:
        os.close(fd)
