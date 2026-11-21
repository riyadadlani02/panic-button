"""Shared types; every later module imports these."""
from dataclasses import dataclass, field
from enum import StrEnum


class Phase(StrEnum):
    FREEZE = "freeze"
    PURGE = "purge"


class Tier(StrEnum):
    API = "api"
    GUIDED = "guided"


class Evidence(StrEnum):
    VERIFIED = "verified"
    ACCEPTED = "accepted"
    OWNER_CONFIRMED = "owner_confirmed"


class Status(StrEnum):
    LOCKED = "locked"
    NEEDS_YOU = "needs_you"
    STILL_OPEN = "still_open"


class WatchPolicy(StrEnum):
    REAPPLY = "reapply"
    REPORT = "report"
    NONE = "none"


class Severity(StrEnum):
    TRIGGER = "trigger"
    NOTICE = "notice"


@dataclass(frozen=True)
class Finding:
    account: str
    code: str
    severity: Severity
    text: str
    items: tuple[str, ...] = ()
    key: str = ""  # an event's stable identity, so a re-read log never reports it twice; "" = always new


@dataclass(frozen=True)
class Account:
    id: str
    provider: str
    protected: bool = False


@dataclass(frozen=True)
class Step:
    account: str
    action: str
    phase: Phase
    tier: Tier
    title: str
    link: str | None = None
    watch: WatchPolicy = WatchPolicy.NONE
    lingers_s: int = 0
    after_read: bool = False  # starts once the account's first read is done, so its evidence is captured


@dataclass
class Result:
    step: Step
    status: Status
    evidence: Evidence | None = None
    detail: str = ""
    at: float = 0.0


@dataclass
class Outcome:
    results: list[Result]
    touched: dict[str, list[str]]
    started_at: float
    removed: dict[str, list[str]] = field(default_factory=dict)  # per account: "category: item" the press took away
    triggers: list[str] = field(default_factory=list)  # what made the guard press, when it did


Edges = list[tuple[str, str]]  # (a, b): control of a can reset b
Snapshot = dict[str, list[str]]  # category -> human-readable items
