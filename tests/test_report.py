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
    assert "unknown" in md and "safe" not in md.lower() and md.count("Nothing.") == 5


def test_freeze_time_is_measured():
    r = Result(Step("mail", "f", Phase.FREEZE, Tier.API, "f"), Status.LOCKED, Evidence.VERIFIED, at=130.0)
    assert report.render(Outcome([r], {}, 100.0), now=200.0)[1]["freeze_seconds"] == 30.0


def test_freeze_is_none_when_a_freeze_step_is_not_locked(outcome):
    assert report.render(outcome, now=1.0)[1]["freeze_seconds"] is None
    assert "not complete" in report.render(outcome, now=1.0)[0]


def test_untrusted_text_cannot_forge_a_heading():
    r = Result(Step("mail", "x", Phase.FREEZE, Tier.API, "T"), Status.STILL_OPEN, detail="bad\n## Locked")
    md, data = report.render(Outcome([r], {"mail": ["f\n## Locked"]}, 0.0), now=1.0)
    assert sum(line.startswith("## Locked") for line in md.splitlines()) == 1
    assert data["still_open"][0]["detail"] == "bad\n## Locked" and data["touched"]["mail"] == ["f\n## Locked"]


def test_locked_without_evidence_is_rendered():
    r = Result(Step("mail", "x", Phase.FREEZE, Tier.API, "Odd step"), Status.LOCKED, None)
    md, _ = report.render(Outcome([r], {}, 0.0), now=1.0)
    assert "### Evidence not recorded" in md and "Odd step" in md


def test_rendered_details(outcome):
    md, _ = report.render(outcome, now=1.0)
    assert "- `mail`: E" in md
    only_verified = Outcome([outcome.results[0]], {"mail": ["a"], "bank": []}, 0.0)
    md, _ = report.render(only_verified, now=1.0)
    assert "### Verified" in md and "### Accepted by provider" not in md and "### Owner confirmed" not in md
    assert "### `mail`" in md and "- `a`" in md and "### `bank`" not in md


def test_lingering_line_carries_utc_time():
    r = Result(Step("mail", "s", Phase.FREEZE, Tier.API, "Sign out", lingers_s=3600), Status.LOCKED, Evidence.ACCEPTED, at=0.0)
    md, _ = report.render(Outcome([r], {}, 0.0), now=10.0)
    assert "may keep working until 1970-01-01T01:00Z" in md


def test_removed_section_follows_touched():
    md, data = report.render(Outcome([], {"mail": ["filters: a"]}, 0.0, {"mail": ["apps: x"], "bank": []}), now=1.0)
    assert md.index("## Attacker may have touched") < md.index("## Removed by this press") < md.index("apps: x")
    assert data["removed"] == {"mail": ["apps: x"], "bank": []}
    md, _ = report.render(Outcome([], {}, 0.0), now=1.0)
    assert md.split("## Removed by this press")[1].split("## Put back during the watch")[0].strip() == "Nothing."


def test_watch_findings_are_listed_under_still_open():
    r = Result(Step("mail", "fwd", Phase.FREEZE, Tier.API, "Fwd"), Status.LOCKED, Evidence.VERIFIED, at=101.0)
    events = [
        {"event": "changed", "account": "mail", "action": "fwd", "at": 50.0},  # before the press
        {"event": "changed", "account": "mail", "action": "fwd", "at": 200.0},
        {"event": "changed", "account": "mail", "action": "fwd", "at": 3700.0},
        {"event": "reapplied", "account": "mail", "action": "fwd", "at": 300.0},
        {"event": "check_failed", "account": "bank", "action": "x", "at": 400.0},
        {"event": "reapply_failed", "account": "mail", "action": "imap", "at": "bad"},
    ]
    md, data = report.render(Outcome([r], {}, 100.0), now=4000.0, watch_events=events)
    still = md.split("## Still open")[1].split("##")[0]
    assert "- `mail`: `fwd` changed (seen 2 times, last 1970-01-01T01:01Z)" in still
    assert "- `bank`: `x` check_failed (seen 1 times" in still and "reapplied" not in still and "imap" not in still
    assert len(data["watch"]) == 2


def test_header_names_press_time_and_targets():
    r = Result(Step("mail", "a", Phase.FREEZE, Tier.API, "A"), Status.LOCKED, Evidence.VERIFIED)
    md, data = report.render(Outcome([r, Result(Step("-", "audit_log", Phase.PURGE, Tier.API, "Audit log"),
                                                Status.STILL_OPEN)], {}, 3600.0), now=1.0)
    assert "1970-01-01T01:00Z" in md.split("## Locked")[0] and "Targeted: `mail`." in md
    assert data["started_at"] == 3600.0 and data["targets"] == ["mail"]


def test_untrusted_text_renders_as_code_not_links():
    r = Result(Step("ma`il", "x", Phase.PURGE, Tier.GUIDED, "Do it", link="https://ok.test/a b"), Status.NEEDS_YOU,
               detail="see [here](https://evil.test)\n<img src=x>")
    md, _ = report.render(Outcome([r], {"ma`il": ["filters: [x](https://evil.test) `y`"]}, 0.0,
                                  {"ma`il": ["apps: <b>x</b>"]}), now=1.0)
    assert "- `ma'il`: Do it (`see [here](https://evil.test) <img src=x>`) `https://ok.test/a b`" in md
    assert "- `filters: [x](https://evil.test) 'y'`" in md and "- `apps: <b>x</b>`" in md


def test_triggers_section_is_code_spanned_and_after_the_header(outcome):
    outcome.triggers = ["rule_hides_mail: a rule that hides mail", "x: line\n## Fake `heading`"]
    md, _ = report.render(outcome, now=1000.0)
    assert "## What triggered this press" in md
    assert md.index("## What triggered this press") < md.index("## Locked")
    assert "- `rule_hides_mail: a rule that hides mail`" in md
    assert "- `x: line ## Fake 'heading'`" in md


def test_no_triggers_no_section(outcome):
    assert "What triggered" not in report.render(outcome, now=1000.0)[0]
