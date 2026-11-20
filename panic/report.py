"""Owner-facing lockdown report; states only what was proven and what is still open."""
from datetime import UTC, datetime

from .model import Evidence, Outcome, Phase, Result, Status

FREEZE_TARGET_S = 60
_EVIDENCE = [
    (Evidence.VERIFIED, "Verified"),
    (Evidence.ACCEPTED, "Accepted by provider"),
    (Evidence.OWNER_CONFIRMED, "Owner confirmed"),
]


def _utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%MZ")


def _clean(text: str) -> str:
    # Untrusted text must not be able to start a Markdown line of its own.
    return " ".join(str(text).split())


def _item(r: Result, detail: str | None = None) -> dict:
    return {
        "account": r.step.account,
        "action": r.step.action,
        "title": r.step.title,
        "evidence": r.evidence.value if r.evidence else None,
        "detail": r.detail if detail is None else detail,
        "link": r.step.link,
    }


def _freeze_seconds(outcome: Outcome) -> float | None:
    freeze = [r for r in outcome.results if r.step.phase == Phase.FREEZE]
    if not freeze or any(r.status != Status.LOCKED for r in freeze):
        return None
    return max(r.at for r in freeze) - outcome.started_at


def _lines(items: list[dict], link: bool = False) -> list[str]:
    if not items:
        return ["Nothing."]
    out = []
    for i in items:
        line = f"- {_clean(i['account'])}: {_clean(i['title'])}"
        if i["detail"]:
            line += f" ({_clean(i['detail'])})"
        if link and i["link"]:
            line += f" {_clean(i['link'])}"
        out.append(line)
    return out


def render(outcome: Outcome, now: float) -> tuple[str, dict]:
    rs = outcome.results
    locked = [_item(r) for r in rs if r.status == Status.LOCKED]
    needs = [_item(r) for r in rs if r.status == Status.NEEDS_YOU]
    still = [_item(r) for r in rs if r.status == Status.STILL_OPEN]
    still += [
        _item(r, f"access granted before the press may keep working until {_utc(r.at + r.step.lingers_s)}")
        for r in rs
        if r.status == Status.LOCKED and r.step.lingers_s > 0 and r.at + r.step.lingers_s > now
    ]
    freeze = _freeze_seconds(outcome)
    data = {
        "locked": locked,
        "needs_you": needs,
        "still_open": still,
        "touched": outcome.touched,
        "removed": outcome.removed,
        "freeze_seconds": freeze,
    }

    head = (
        f"Freeze took {freeze:.0f}s (target {FREEZE_TARGET_S}s)."
        if freeze is not None
        else f"Freeze is not complete (target {FREEZE_TARGET_S}s)."
    )
    md = ["# Lockdown report", "", head, "", "## Locked", ""]
    if not locked:
        md += ["Nothing.", ""]
    for ev, label in [*_EVIDENCE, (None, "Evidence not recorded")]:
        items = [i for i in locked if i["evidence"] == (ev.value if ev else None)]
        if items:
            md += [f"### {label}", "", *_lines(items), ""]
    md += ["## Needs you", "", *_lines(needs, link=True), "", "## Still open", "", *_lines(still), ""]
    md += _per_account("Attacker may have touched", outcome.touched)
    md += _per_account("Removed by this press", outcome.removed)
    return "\n".join(md).rstrip("\n") + "\n", data


def _per_account(heading: str, items: dict[str, list[str]]) -> list[str]:
    md = [f"## {heading}", ""]
    if not any(items.values()):
        md += ["Nothing.", ""]
    for acct, ts in items.items():
        if ts:
            md += [f"### {_clean(acct)}", "", *(f"- {_clean(t)}" for t in ts), ""]
    return md
