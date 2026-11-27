import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from test_guard import NOTICE, TRIG, conn  # noqa: E402

from panic.guard import _key, guard_once, new_state  # noqa: E402
from panic.model import Account, Finding, Severity  # noqa: E402

EV = Finding("mail", "new_device", Severity.TRIGGER, "x", key="e1")
OTHER = Finding("mail", "changed", Severity.NOTICE, "x", ("b",))


def run(c, state, t=1e6, wait=900, dry_run=False, snap=None):
    acts, asked, accepted = [], [], []
    lines = guard_once([Account("mail", "fake")], [], {"mail": c}, {"mail": {}}, set(), state, "press",
                       lambda targets, f: acts.append(targets), lambda f, e: None, lambda: None, lambda: t,
                       dry_run, wait, lambda a, fs, d: asked.append((a, fs, d)), lambda a, s: accepted.append((a, s)))
    return lines, acts, asked, accepted


def test_trigger_asks_once_and_does_not_act_before_deadline():
    state, c = new_state(), conn([TRIG])
    _, acts, asked, _ = run(c, state, 1e6)
    _, acts2, asked2, _ = run(c, state, 1e6 + 10)
    assert acts == acts2 == [] and len(asked) == 1 and asked2 == []
    assert state["asks"][_key(TRIG)]["deadline"] == 1e6 + 900


def test_lock_answer_acts_on_next_pass():
    state, c = new_state(), conn([TRIG])
    run(c, state)
    state["asks"][_key(TRIG)]["answer"] = "lock"
    _, acts, *_ = run(c, state, 1e6 + 10)
    assert acts == [["mail"]] and state["asks"] == {}


def test_accept_answer_saves_snapshot_and_clears():
    state, c = new_state(), conn([NOTICE])
    run(c, state)
    state["asks"][_key(NOTICE)]["answer"] = "accept"
    _, acts, _, accepted = run(c, state, 1e6 + 10)
    assert accepted == [("mail", {})] and state["asks"] == {} and acts == []


def test_unanswered_trigger_acts_at_deadline():
    state, c = new_state(), conn([TRIG])
    run(c, state)
    assert run(c, state, 1e6 + 899)[1] == []
    assert run(c, state, 1e6 + 900)[1] == [["mail"]]


def test_unanswered_notice_is_accepted_at_deadline():
    state, c = new_state(), conn([NOTICE])
    run(c, state)
    assert run(c, state, 1e6 + 899)[3] == []
    _, acts, _, accepted = run(c, state, 1e6 + 900)
    assert len(accepted) == 1 and acts == [] and state["asks"] == {}


def test_accept_refused_when_a_new_finding_appeared():
    state, c = new_state(), conn([NOTICE])
    run(c, state)
    state["asks"][_key(NOTICE)]["answer"] = "accept"
    c.findings = [NOTICE, OTHER]
    _, acts, asked, accepted = run(c, state, 1e6 + 10)
    assert accepted == [] and _key(OTHER) in state["asks"] and asked[0][1] == [OTHER]


def test_vanished_finding_closes_its_question():
    state, c = new_state(), conn([TRIG])
    run(c, state)
    c.findings = []
    _, acts, _, accepted = run(c, state, 1e6 + 2000)
    assert acts == [] and accepted == [] and state["asks"] == {}


def test_event_trigger_accept_closes_without_snapshot():
    state, c = new_state(), conn(events=[EV])
    run(c, state)
    assert state["asks"][_key(EV)]["event"] is True
    state["asks"][_key(EV)]["answer"] = "accept"
    _, acts, _, accepted = run(c, state, 1e6 + 10)
    assert state["asks"] == {} and acts == [] and accepted == []


def test_event_trigger_unanswered_acts():
    state, c = new_state(), conn(events=[EV])
    run(c, state)
    c.event_findings = []
    assert run(c, state, 1e6 + 900)[1] == [["mail"]]


def test_dry_run_prints_would_ask_and_saves_nothing():
    state, c = new_state(), conn([TRIG])
    lines, acts, asked, _ = run(c, state, dry_run=True)
    assert any(l.startswith("would ask mail") for l in lines) and state["asks"] == {} and not acts and not asked


def test_alert_mode_and_wait_zero_unchanged():
    for kw in ({"wait": 0}, {}):
        state = new_state()
        acts = []
        lines = guard_once([Account("mail", "fake")], [], {"mail": conn([TRIG])}, {"mail": {}}, set(), state,
                           "alert" if kw == {} else "press", lambda t, f: acts.append(t), lambda f, e: None,
                           lambda: None, lambda: 1e6, False, **({"wait": 900} if kw == {} else kw))
        assert state["asks"] == {}
        assert bool(acts) == (kw != {})
