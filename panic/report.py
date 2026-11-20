"""Owner-facing lockdown report; states only what was proven and what is still open."""
from datetime import UTC, datetime

from .model import Evidence, Outcome, Phase, Result, Status

FREEZE_TARGET_S = 60
WATCH_FINDINGS = ("changed", "reapply_failed", "check_failed")
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


def _code(text: str) -> str:
    # A code span renders attacker-written text inert: no links, images or HTML.
    return "`" + _clean(text).replace("`", "'") + "`"


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
    out = []
    for i in items:
        line = f"- {_code(i['account'])}: {_clean(i['title'])}"
        if i["detail"]:
            line += f" ({_code(i['detail'])})"
        if link and i["link"]:
            line += f" {_code(i['link'])}"
        out.append(line)
    return out


def _watch_findings(events, since: float, kinds=WATCH_FINDINGS) -> list[dict]:
    """What the watch saw after the press, one entry per (account, action, event) with a count."""
    seen: dict[tuple, dict] = {}
    for e in events:
        at = e.get("at")
        if e.get("event") not in kinds or not isinstance(at, (int, float)) or at <= since:
            continue
        key = (str(e.get("account")), str(e.get("action")), e["event"])
        f = seen.setdefault(key, {"account": key[0], "action": key[1], "event": key[2], "count": 0, "last": at,
                                  "removed": []})
        f["count"] += 1
        f["last"] = max(f["last"], at)
        items = e.get("removed")
        f["removed"] += [str(i) for i in items if str(i) not in f["removed"]] if isinstance(items, list) else []
    return list(seen.values())


def render(outcome: Outcome, now: float, watch_events=()) -> tuple[str, dict]:
    rs = outcome.results
    locked = [_item(r) for r in rs if r.status == Status.LOCKED]
    needs = [_item(r) for r in rs if r.status == Status.NEEDS_YOU]
    still = [_item(r) for r in rs if r.status == Status.STILL_OPEN]
    still += [
        _item(r, f"access granted before the press may keep working until {_utc(r.at + r.step.lingers_s)}")
        for r in rs
        if r.status == Status.LOCKED and r.step.lingers_s > 0 and r.at + r.step.lingers_s > now
    ]
    watch = _watch_findings(watch_events, outcome.started_at)
    put_back = _watch_findings(watch_events, outcome.started_at, ("reapplied",))
    titles = {(r.step.account, r.step.action): r.step.title for r in rs}
    targets = list(dict.fromkeys(r.step.account for r in rs if r.step.account != "-"))
    freeze = _freeze_seconds(outcome)
    data = {
        "started_at": outcome.started_at,
        "targets": targets,
        "locked": locked,
        "needs_you": needs,
        "still_open": still,
        "watch": watch,
        "touched": outcome.touched,
        "removed": outcome.removed,
        "put_back": put_back,
        "freeze_seconds": freeze,
    }

    head = (
        f"Freeze took {freeze:.0f}s (target {FREEZE_TARGET_S}s)."
        if freeze is not None
        else f"Freeze is not complete (target {FREEZE_TARGET_S}s)."
    )
    md = ["# Lockdown report", "", f"Press at {_utc(outcome.started_at)} (UTC). "
          f"Targeted: {', '.join(_code(t) for t in targets) or 'none'}.", "", head, "", "## Locked", ""]
    if not locked:
        md += ["Nothing.", ""]
    for ev, label in [*_EVIDENCE, (None, "Evidence not recorded")]:
        items = [i for i in locked if i["evidence"] == (ev.value if ev else None)]
        if items:
            md += [f"### {label}", "", *_lines(items), ""]
    open_lines = _lines(still) + [
        f"- {_code(w['account'])}: {_code(w['action'])} {w['event']} (seen {w['count']} times, last {_utc(w['last'])})"
        for w in watch]
    md += ["## Needs you", "", *(_lines(needs, link=True) or ["Nothing."]), ""]
    md += ["## Still open", "", *(open_lines or ["Nothing."]), ""]
    md += _per_account("Attacker may have touched", outcome.touched)
    md += _per_account("Removed by this press", outcome.removed)
    md += ["## Put back during the watch", ""]
    for p in put_back:
        title = titles.get((p["account"], p["action"]))
        md += [f"- {_code(p['account'])}: {_clean(title) if title else _code(p['action'])} "
               f"put back {p['count']} times, last {_utc(p['last'])}", *(f"  - {_code(i)}" for i in p["removed"])]
    md += [] if put_back else ["Nothing."]
    return "\n".join(md).rstrip("\n") + "\n", data


def _per_account(heading: str, items: dict[str, list[str]]) -> list[str]:
    md = [f"## {heading}", ""]
    if not any(items.values()):
        md += ["Nothing.", ""]
    for acct, ts in items.items():
        if ts:
            md += [f"### {_code(acct)}", "", *(f"- {_code(t)}" for t in ts), ""]
    return md
