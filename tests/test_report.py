import pytest

from panic import report
from panic.model import Evidence, Outcome, Phase, Result, Status, Step, Tier


def _r(action, status, evidence=None, link=None, at=0.0):
    return Result(Step("mail", action, Phase.FREEZE, Tier.API, action.title(), link=link), status, evidence, at=at)


@pytest.fixture
def outcome():
    return Outcome([
        _r("a", Status.LOCKED, Evidence.VERIFIED),
        _r("b", Status.LOCKED, Evidence.ACCEPTED),
        _r("c", Status.LOCKED, Evidence.OWNER_CONFIRMED),
        _r("d", Status.NEEDS_YOU, link="https://example.test/step"),
        _r("e", Status.STILL_OPEN),
    ], {}, 0.0)


def test_sections_and_evidence_are_never_merged(outcome):
    md, data = report.render(outcome, now=1000.0)
    heads = ["## Locked", "## Needs you", "## Still open", "## Attacker may have touched"]
    assert [md.index(h) for h in heads] == sorted(md.index(h) for h in heads)
    assert "### Verified" in md and "### Accepted by provider" in md and "### Owner confirmed" in md
    assert "https://example.test/step" in md
    assert len(data["locked"]) == 3 and {i["evidence"] for i in data["locked"]} == {"verified", "accepted", "owner_confirmed"}


def test_lingering_access_is_listed_as_open_until_it_expires():
    r = Result(Step("mail", "signout", Phase.FREEZE, Tier.API, "Sign out", lingers_s=3600), Status.LOCKED, Evidence.ACCEPTED, at=500.0)
    _, data = report.render(Outcome([r], {}, 490.0), now=1000.0)
    assert any("may keep working until" in i["detail"] for i in data["still_open"])
    _, later = report.render(Outcome([r], {}, 490.0), now=5000.0)
    assert later["still_open"] == []


def test_no_safe_claim_and_empty_sections_say_nothing():
    md, _ = report.render(Outcome([], {"mail": ["unknown: could not read (x)"]}, 0.0), now=1.0)
    assert "unknown" in md and "safe" not in md.lower() and md.count("Nothing.") == 3


def test_freeze_time_is_measured():
    r = Result(Step("mail", "f", Phase.FREEZE, Tier.API, "f"), Status.LOCKED, Evidence.VERIFIED, at=130.0)
    assert report.render(Outcome([r], {}, 100.0), now=200.0)[1]["freeze_seconds"] == 30.0


def test_freeze_is_none_when_a_freeze_step_is_not_locked(outcome):
    assert report.render(outcome, now=1.0)[1]["freeze_seconds"] is None
    assert "not complete" in report.render(outcome, now=1.0)[0]
