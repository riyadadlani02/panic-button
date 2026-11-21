import json, pytest
from panic.model import Severity
from panic.signals import drift, gmail_rule_code

def rule(**action): return json.dumps({"action": action, "criteria": {"from": "x"}}, sort_keys=True)

def test_rule_codes():
    assert gmail_rule_code(rule(forward="a@evil.test"), None) == "rule_forwards_outside"
    assert gmail_rule_code(rule(forward="a@corp.test"), "corp.test") is None
    assert gmail_rule_code(rule(forward="a@evil.test"), "corp.test") == "rule_forwards_outside"
    assert gmail_rule_code(rule(addLabelIds=["TRASH"]), None) == "rule_hides_mail"
    assert gmail_rule_code(rule(removeLabelIds=["INBOX", "UNREAD"]), None) == "rule_hides_mail"
    assert gmail_rule_code(rule(addLabelIds=["STARRED"]), None) is None
    assert gmail_rule_code("not json", None) == "rule_hides_mail"

def test_drift_splits_triggers_from_notices():
    base = {"filters": ["keep"], "pop": []}
    snap = {"filters": ["keep", "bad", "label"], "pop": ["pop"]}
    out = drift("a@x", base, snap, lambda c, i: {"bad": "rule_hides_mail", "pop": "pop_enabled"}.get(i))
    by = {f.code: f for f in out}
    assert by["rule_hides_mail"].severity is Severity.TRIGGER and by["rule_hides_mail"].items == ("filters: bad",)
    assert by["pop_enabled"].severity is Severity.TRIGGER
    assert by["changed"].severity is Severity.NOTICE and by["changed"].items == ("filters: label",)

def test_drift_matches_baseline_returns_nothing():
    assert drift("a@x", {"filters": ["k"]}, {"filters": ["k"]}, lambda c, i: "rule_hides_mail") == []

def test_drift_fails_closed_without_a_baseline_category():
    with pytest.raises(KeyError, match="no baseline recorded for filters on a@x"):
        drift("a@x", {}, {"filters": ["k"]}, lambda c, i: None)
