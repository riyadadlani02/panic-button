"""Connector contract, plan compilation, and the press that runs a plan and records evidence."""
import time
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Protocol

from panic.graph import lock_order, resetters
from panic.model import Account, Edges, Evidence, Outcome, Phase, Result, Snapshot, Status, Step, Tier


class Connector(Protocol):
    # run and check are called concurrently from several threads and must be thread-safe.
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
          dry_run: bool = False, now: Callable[[], float] = time.time) -> Outcome:
    started = now()
    provider = {a.id: a.provider for a in accounts}
    touched: dict[str, list[str]] = {}
    for a in accounts:
        if a.protected or a.provider not in connectors:  # break-glass is never touched, reads included
            continue
        try:
            touched[a.id] = outside_baseline(baselines.get(a.id, {}), connectors[a.provider].snapshot(a))
        except Exception as e:
            touched[a.id] = [f"unknown: could not read ({e})"]

    def done(step, status, evidence=None, detail=""):
        return Result(step, status, evidence, detail, now())

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

    if dry_run:
        results = [done(s, Status.STILL_OPEN, detail="dry run") for s in plan]
    else:
        finished: dict[Step, Result] = {}
        futures: dict[Step, Future] = {}
        guided = [s for s in plan if s.tier is Tier.GUIDED]
        # Hand-managed pool: leaving a `with` block would join in-flight provider calls on interrupt.
        pool = ThreadPoolExecutor(max_workers=16)
        try:
            for phase in (Phase.FREEZE, Phase.PURGE):
                steps = [s for s in plan if s.tier is Tier.API and s.phase == phase]
                futures.update({s: pool.submit(api, s) for s in steps})
                for s in steps:
                    finished[s] = futures[s].result()
            for step in guided:
                if not confirm(step):
                    finished[step] = done(step, Status.NEEDS_YOU)
                    continue
                try:
                    ok = readback(step)
                except Exception as e:
                    finished[step] = done(step, Status.STILL_OPEN, detail=str(e))
                    continue
                if ok is False:
                    finished[step] = done(step, Status.NEEDS_YOU, detail="marked done but the read-back still shows it open")
                else:
                    finished[step] = done(step, Status.LOCKED, Evidence.VERIFIED if ok is True else Evidence.OWNER_CONFIRMED)
        except (KeyboardInterrupt, Exception):  # Ctrl-C, EOF or a raising confirm: keep what is gathered
            pass
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
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
        results = [finished[s] for s in plan]

        has_steps = {s.account for s in plan}
        open_ = {a.id for a in accounts if not a.protected and a.id not in has_steps}
        open_ |= {r.step.account for r in results if r.step.phase is Phase.FREEZE and r.status is not Status.LOCKED}
        for a in accounts:
            bad = sorted(resetters(a.id, edges) & open_)
            if bad and not a.protected:
                results.append(done(Step(a.id, "reopenable", Phase.FREEZE, Tier.API, "Re-openable"),
                                    Status.STILL_OPEN, detail="re-openable from " + ", ".join(bad)))

    for r in results[:]:  # calling thread only: the log writer is not concurrency-safe
        try:
            log({"account": r.step.account, "action": r.step.action, "phase": r.step.phase, "tier": r.step.tier,
                 "status": r.status, "evidence": r.evidence, "detail": r.detail})
        except Exception as e:  # results must survive a broken log
            results.append(done(Step("-", "audit_log", Phase.PURGE, Tier.API, "Audit log"), Status.STILL_OPEN,
                                detail=f"could not write the audit log: {e}"))
            break
    return Outcome(results, touched, started)
