"""Scriptable connector for engine tests."""
from dataclasses import replace

from panic.model import Account, Finding, Snapshot, Step


class FakeConnector:
    def __init__(self, provider="fake", steps=(), fail=(), no_readback=()):
        self.provider = provider
        self.steps = list(steps)
        self.fail = set(fail)
        self.no_readback = set(no_readback)
        self.ran: list[str] = []
        self.state: dict[str, bool] = {}
        self.snap: Snapshot = {}
        self.findings: list[Finding] = []
        self.event_findings: list[Finding] = []

    @staticmethod
    def _key(step: Step) -> str:
        return f"{step.account}/{step.action}"

    def catalog(self, account: Account) -> list[Step]:
        return [replace(s, account=account.id) for s in self.steps]

    def snapshot(self, account: Account) -> Snapshot:
        return self.snap

    def run(self, step: Step, baseline: Snapshot) -> None:
        key = self._key(step)
        self.ran.append(key)
        if key in self.fail:
            raise RuntimeError("boom")
        self.state[key] = True

    def check(self, step: Step, baseline: Snapshot) -> bool | None:
        if step.action in self.no_readback:
            return None
        return self.state.get(self._key(step), False)

    def signals(self, account: Account, snapshot: Snapshot, baseline: Snapshot) -> list[Finding]:
        return self.findings

    def events(self, account: Account, since: float) -> list[Finding]:
        return self.event_findings
