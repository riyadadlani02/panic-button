"""Connector contract, plan compilation, the press that runs a plan and records evidence, and the watch that keeps it locked."""
import contextlib
import time
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor, as_completed, wait
from typing import Protocol

from panic.graph import lock_order, resetters
from panic.model import Account, Edges, Evidence, Outcome, Phase, Result, Snapshot, Status, Step, Tier, WatchPolicy

# Steps that lock the person out; `panic release` lifts them on purpose, so the watch never puts them back.
LOCK_ACTIONS = {"suspend", "disable", "deactivate"}


class Connector(Protocol):
    # run and check are called concurrently from several threads and must be thread-safe.
    # Optional, looked up with getattr: signals(account, snapshot, baseline) -> list[Finding]
    # and events(account, since: float) -> list[Finding].
    provider: str

    def catalog(self, account: Account) -> list[Step]: ...  # no network; order = guided presentation order
    def snapshot(self, account: Account) -> Snapshot: ...  # read-only
    def run(self, step: Step, baseline: Snapshot) -> None: ...  # safe to call twice
    def check(self, step: Step, baseline: Snapshot) -> bool | None: ...  # None = no read-back exists


def compile_plan(accounts: list[Account], edges: Edges, connectors: dict[str, Connector]) -> list[Step]:
    # Protected accounts never get steps; accounts without a connector have nothing to run.
    by_id = {a.id: a for a in accounts if not a.protected and a.provider in connectors}
    steps = {i: connectors[a.provider].catalog(a) for i, a in by_id.items()}
    order = lock_order(list(by_id), edges)
    return [s for phase in (Phase.FREEZE, Phase.PURGE) for i in order for s in steps[i] if s.phase == phase]


def outside_baseline(baseline: Snapshot, current: Snapshot) -> list[str]:
    return sorted(f"{cat}: {item}" for cat, items in current.items()
                  for item in items if item not in baseline.get(cat, []))


def press(plan: list[Step], accounts: list[Account], edges: Edges, connectors: dict[str, Connector],
          baselines: dict[str, Snapshot], confirm: Callable[[Step], bool], log: Callable[[dict], None],
          dry_run: bool = False, now: Callable[[], float] = time.time,
          progress: Callable[[str], None] = lambda s: None,
          checkpoint: Callable[[Outcome], None] = lambda o: None, lock=None) -> Outcome:
    started = now()
    provider = {a.id: a.provider for a in accounts}
    by_id = {a.id: a for a in accounts}
    # Only accounts with steps are read: a one-user press must not walk the whole tenant.
    targets = [i for i in dict.fromkeys(s.account for s in plan) if not by_id[i].protected]
    touched: dict[str, list[str]] = {}
    removed: dict[str, list[str]] = {}
    first: dict[str, Snapshot] = {}
    extra: list[Result] = []  # failures of the tool's own bookkeeping, listed last
    log_ok = True

    def done(step, status, evidence=None, detail=""):
        return Result(step, status, evidence, detail, now())

    def snap(i: str) -> Snapshot:
        return connectors[provider[i]].snapshot(by_id[i])

    def record(r: Result) -> None:  # calling thread only: the log writer is not concurrency-safe
        nonlocal log_ok
        if not log_ok:
            return
        try:
            log({"account": r.step.account, "action": r.step.action, "phase": r.step.phase, "tier": r.step.tier,
                 "status": r.status, "evidence": r.evidence, "detail": r.detail})
        except Exception as e:  # results must survive a broken log
            log_ok = False
            extra.append(done(Step("-", "audit_log", Phase.PURGE, Tier.API, "Audit log"), Status.STILL_OPEN,
                              detail=f"could not write the audit log: {e}"))

    def readback(step: Step) -> bool | None:
        ok = connectors[provider[step.account]].check(step, baselines.get(step.account, {}))
        if ok is not None and not isinstance(ok, bool):
            raise ValueError(f"unexpected check result {ok!r}")
        return ok

    def api(step: Step) -> Result:  # never raises: one failure must not stop the rest
        try:
            connectors[provider[step.account]].run(step, baselines.get(step.account, {}))
            ok = readback(step)
        except Exception as e:
            return done(step, Status.STILL_OPEN, detail=str(e))
        if ok is False:
            return done(step, Status.STILL_OPEN, detail="provider accepted the call but the read-back still shows it open")
        return done(step, Status.LOCKED, Evidence.VERIFIED if ok is True else Evidence.ACCEPTED)

    def api_after(read: Future, step: Step) -> Result:
        # Queued after its read, and the pool is FIFO: the read is already running or done, so no worker deadlocks.
        wait([read])  # a failed read still lets the lock run: the lock matters more than the evidence
        return api(step)

    if dry_run:
        for i in targets:
            try:
                touched[i] = outside_baseline(baselines.get(i, {}), snap(i))
            except Exception as e:
                touched[i] = [f"unknown: could not read ({e})"]
        results = [done(s, Status.STILL_OPEN, detail="dry run") for s in plan]
        for r in results:
            record(r)
        return Outcome(results + extra, touched, started)

    finished: dict[Step, Result] = {}
    futures: dict[Step, Future] = {}
    snaps: dict[str, Future] = {}
    guided = [s for s in plan if s.tier is Tier.GUIDED]

    def decide(step: Step, r: Result) -> None:
        finished[step] = r
        record(r)

    def take_first(i: str) -> None:
        f = snaps.get(i)
        if f is None or not f.done() or f.cancelled():
            touched[i] = ["unknown: not read (interrupted)"]
        elif f.exception() is not None:
            touched[i] = [f"unknown: could not read ({f.exception()})"]
        else:
            first[i] = f.result()
            touched[i] = outside_baseline(baselines.get(i, {}), first[i])

    # Hand-managed pool: leaving a `with` block would join in-flight provider calls on interrupt.
    pool = ThreadPoolExecutor(max_workers=16)
    held = contextlib.ExitStack()  # the API phases only: a guided question must not hold it
    try:
        if lock is not None:
            held.enter_context(lock)
        for phase in (Phase.FREEZE, Phase.PURGE):
            steps = [s for s in plan if s.tier is Tier.API and s.phase == phase]
            progress(f"{phase.value.title()}: {len(steps)} actions")
            if phase is Phase.FREEZE:
                for i in targets:  # each read is queued beside its own freeze, so it never holds up the first lock
                    snaps[i] = pool.submit(snap, i)
                    futures.update({s: pool.submit(api_after, snaps[i], s) if s.after_read else pool.submit(api, s)
                                    for s in steps if s.account == i})
            else:
                futures.update({s: pool.submit(api, s) for s in steps})
            pending = {futures[s]: s for s in steps}
            for f in as_completed(pending):
                decide(pending[f], f.result())
            if phase is Phase.FREEZE:  # purge removes items, so the first read must be in hand before it starts
                wait(snaps.values())
                for i in targets:
                    take_first(i)
        after = {i: pool.submit(snap, i) for i in first}
        wait(after.values())
        for i in targets:
            f = after.get(i)
            if f is None:
                removed[i] = list(touched[i])  # the first read already failed
            elif f.exception() is not None:
                removed[i] = [f"unknown: could not read ({f.exception()})"]
            else:
                removed[i] = outside_baseline(f.result(), first[i])
        try:
            checkpoint(Outcome([finished[s] for s in plan if s in finished] + extra, dict(touched), started,
                               dict(removed)))
        except Exception as e:  # saving progress must never stop the press
            extra.append(done(Step("-", "checkpoint", Phase.PURGE, Tier.API, "Save progress"), Status.STILL_OPEN,
                              detail=f"could not save progress: {e}"))
        held.close()
        if guided:
            progress(f"Guided: {len(guided)} steps for you")
        for step in guided:
            if not confirm(step):
                decide(step, done(step, Status.NEEDS_YOU))
                continue
            try:
                ok = readback(step)
            except Exception as e:
                decide(step, done(step, Status.STILL_OPEN, detail=str(e)))
                continue
            if ok is False:
                decide(step, done(step, Status.NEEDS_YOU, detail="marked done but the read-back still shows it open"))
            else:
                decide(step, done(step, Status.LOCKED, Evidence.VERIFIED if ok is True else Evidence.OWNER_CONFIRMED))
    except (KeyboardInterrupt, Exception):  # Ctrl-C, EOF or a raising confirm: keep what is gathered
        pass
    finally:
        held.close()
        pool.shutdown(wait=False, cancel_futures=True)
    late: list[Result] = []
    for s in plan:
        if s in finished:
            continue
        f = futures.get(s)
        if f is not None and f.done() and not f.cancelled() and f.exception() is None:
            finished[s] = f.result()  # finished while the interrupt was handled
        elif s.tier is Tier.API:
            finished[s] = done(s, Status.STILL_OPEN, detail="interrupted")
        else:
            finished[s] = done(s, Status.NEEDS_YOU, detail="not asked")
        late.append(finished[s])
    for i in targets:
        if i not in touched:
            take_first(i)
        removed.setdefault(i, ["unknown: not read (interrupted)"])  # never "Nothing." after a purge ran
    results = [finished[s] for s in plan]

    # Every account counts as a possible open root, but only targets get a re-openable line.
    open_ = {a.id for a in accounts if not a.protected and a.id not in targets}
    open_ |= {r.step.account for r in results if r.step.phase is Phase.FREEZE and r.status is not Status.LOCKED}
    for i in targets:
        bad = sorted(resetters(i, edges) & open_)
        if bad:
            r = done(Step(i, "reopenable", Phase.FREEZE, Tier.API, "Re-openable"),
                     Status.STILL_OPEN, detail="re-openable from " + ", ".join(bad))
            results.append(r)
            late.append(r)
    try:
        for r in late:
            record(r)
    except KeyboardInterrupt:  # results are kept; only these log lines are lost
        pass
    return Outcome(results + extra, touched, started, removed)


def watch_once(results: list[Result], connectors: dict[str, Connector], accounts: list[Account],
               baselines: dict[str, Snapshot], released: set[str], log: Callable[[dict], None]) -> list[str]:
    provider = {a.id: a.provider for a in accounts}
    by_id = {a.id: a for a in accounts}
    lines: list[str] = []
    log_failed = False

    def note(event: str, step: Step, detail: str, line: str, removed: list[str] | None = None):
        nonlocal log_failed
        lines.append(line)
        entry = {"event": event, "account": step.account, "action": step.action, "detail": detail}
        if removed is not None:  # its own key, so the log writer can withhold it
            entry["removed"] = removed
        try:
            log(entry)
        except Exception as e:  # a broken log must not stop the watch
            if not log_failed:
                log_failed = True
                lines.append(f"could not write the audit log: {e}")

    for r in results:
        step = r.step
        if r.status is not Status.LOCKED or step.watch is WatchPolicy.NONE:
            continue
        if provider.get(step.account) not in connectors:
            continue
        if step.action in LOCK_ACTIONS and step.account in released:
            continue
        conn, base = connectors[provider[step.account]], baselines.get(step.account, {})
        name = f"{step.account}/{step.action}"
        try:
            ok = conn.check(step, base)
            if ok is not None and not isinstance(ok, bool):
                raise ValueError(f"unexpected check result {ok!r}")
        except Exception as e:
            note("check_failed", step, str(e), f"{name}: could not check ({e})")
            continue
        if ok is not False:  # True = unchanged, None = no read-back to watch
            continue
        if step.watch is WatchPolicy.REPORT:
            note("changed", step, "changed since lockdown", f"{name}: changed since lockdown")
            continue
        try:
            before = conn.snapshot(by_id[step.account])
        except Exception as e:
            before, why = None, str(e)
        try:
            conn.run(step, base)
            fixed = conn.check(step, base) is True
            err = "still open after reapply"
        except Exception as e:
            fixed, err = False, str(e)
        try:  # itemised so whatever the re-apply deleted can be restored
            gone = outside_baseline(conn.snapshot(by_id[step.account]), before) if before is not None else None
        except Exception as e:
            gone, why = None, str(e)
        removed = gone if gone is not None else [f"unknown: could not read ({why})"]
        if fixed:
            note("reapplied", step, "put back", f"{name}: was changed, put back", removed)
        else:
            note("reapply_failed", step, err, f"{name}: was changed and could not be put back ({err})", removed)
    return lines


def watch(results, connectors, accounts, baselines, released: Callable[[], set[str]], log,
          hours: float = 24, interval_s: float = 300,
          sleep: Callable[[float], None] = time.sleep, now: Callable[[], float] = time.time) -> None:
    deadline = now() + hours * 3600
    while now() < deadline:
        for line in watch_once(results, connectors, accounts, baselines, released(), log):
            print(line)
        sleep(interval_s)
