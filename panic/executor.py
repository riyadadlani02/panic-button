"""Connector contract and plan compilation."""
from typing import Protocol

from panic.graph import lock_order
from panic.model import Account, Edges, Phase, Snapshot, Step


class Connector(Protocol):
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
