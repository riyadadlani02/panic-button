import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from fake import FakeConnector  # noqa: E402
from test_guard import NOTICE, TRIG, conn  # noqa: E402

from panic.guard import _key, guard_once, new_state  # noqa: E402
from panic.model import Account, Finding, Severity  # noqa: E402
from panic.signals import TEXT  # noqa: E402

EV = Finding("mail", "new_device", Severity.TRIGGER, "x", key="e1")
OTHER = Finding("mail", "changed", Severity.NOTICE, "x", ("b",))


def run(c, state, t=1e6, wait=900, dry_run=False, got=None, base=None):
    acts, asked, accepted = [], [], []
    lines = guard_once([Account("mail", "fake")], [], {"mail": c}, {"mail": base or {}}, set(), state, "press",
                       lambda targets, f: (acts.append(targets), got is not None and got.append(f)),
                       lambda f, e: None, lambda: None, lambda: t,
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


def fwd(*items):
    return Finding("mail", "forwarding_added", Severity.TRIGGER, "x", items)


def test_toggling_a_second_item_does_not_move_the_deadline():
    state, c = new_state(), conn([fwd("a")])
    run(c, state)
    for i, f in enumerate([fwd("a", "b"), fwd("a"), fwd("a", "b")], 1):
        c.findings = [f]
        assert run(c, state, 1e6 + 300 * i - 1)[1] == []
    assert run(c, state, 1e6 + 900)[1] == [["mail"]]


def test_a_replaced_item_keeps_the_first_deadline():
    state, c = new_state(), conn([fwd("a")])
    run(c, state)
    c.findings = [fwd("b")]
    assert run(c, state, 1e6 + 300)[1] == []
    assert run(c, state, 1e6 + 900)[1] == [["mail"]]


def boom(account):
    raise RuntimeError("down")


def test_unreadable_account_acts_on_an_overdue_or_locked_question():
    for answer, t in ((None, 1e6 + 900), ("lock", 1e6 + 10)):
        state, c = new_state(), conn([TRIG])
        run(c, state)
        state["asks"][_key(TRIG)]["answer"] = answer
        c.snapshot = boom
        assert run(c, state, t)[1] == [["mail"]] and state["asks"] == {}


def test_a_failed_accept_reread_does_not_stop_the_pass():
    class FailsThirdRead(FakeConnector):
        reads = 0

        def snapshot(self, account):
            self.reads += 1
            if self.reads == 3:
                raise RuntimeError("down")
            return {}

    mail, bank = FailsThirdRead(), conn()
    mail.findings = [NOTICE]
    state, asked = new_state(), []

    def go(t):
        return guard_once([Account("mail", "fake"), Account("bank", "fake")], [], {"mail": mail, "bank": bank},
                          {"mail": {}, "bank": {}}, set(), state, "press", lambda *a: None, lambda f, e: None,
                          lambda: None, lambda: t, False, 900, lambda a, fs, d: asked.append(a), lambda a, s: None)

    go(1e6)
    state["asks"][_key(NOTICE)]["answer"] = "accept"
    bank.findings = [Finding("bank", "key_added", Severity.TRIGGER, "x", ("k",))]
    lines = go(1e6 + 10)
    assert asked == ["mail", "bank"] and any(TEXT["unreadable"] in x for x in lines)
    assert _key(NOTICE) in state["asks"]


def test_cooling_account_is_not_asked_and_keeps_the_old_path():
    state, c = new_state(), conn([TRIG, NOTICE])
    state["pressed"]["mail"] = 1e6 - 10
    lines, acts, asked, _ = run(c, state)
    lines2, acts2, asked2, _ = run(c, state, 1e6 + 900)
    assert asked == asked2 == [] and state["asks"] == {} and acts == acts2 == []
    assert "mail: the watch is already handling this" in lines and _key(NOTICE) in state["seen"]


def test_lock_on_a_harmless_question_passes_its_finding():
    state, c, got = new_state(), conn([NOTICE]), []
    run(c, state)
    state["asks"][_key(NOTICE)]["answer"] = "lock"
    assert run(c, state, 1e6 + 10, got=got)[1] == [["mail"]] and got == [[NOTICE]]


def test_a_new_question_prints_a_line():
    lines = run(conn([TRIG]), new_state())[0]
    assert "ask mail: x It will be pressed at 14:01:40 unless you answer." in lines


HIDE = Finding("mail", "forwarding_added", Severity.TRIGGER, "y", ("evil@x",))


def test_a_risky_item_toggled_off_and_on_is_acted_on_by_its_first_deadline():
    state, c = new_state(), conn()
    for i in range(48):  # on 10 minutes, off 5, read every 5 minutes
        c.findings = [TRIG] if i % 3 != 2 else []
        if run(c, state, 1e6 + 300 * i)[1]:
            break
    assert 1e6 + 300 * i <= 1e6 + 900 + 300


def test_two_risky_codes_alternating_are_acted_on_by_the_first_deadline():
    state, c = new_state(), conn()
    for i in range(48):
        c.findings = [TRIG] if i % 2 else [HIDE]
        if run(c, state, 1e6 + 300 * i)[1]:
            break
    assert 1e6 + 300 * i == 1e6 + 900


def test_the_floor_expires_after_a_quiet_cooldown():
    from panic.guard import COOLDOWN_S
    state, c = new_state(), conn([TRIG])
    run(c, state)
    c.findings = []
    run(c, state, 1e6 + 300)
    assert state["floors"] == {"mail": 1e6 + 900}
    t = 1e6 + 900 + COOLDOWN_S + 1
    run(c, state, t)
    c.findings = [HIDE]
    _, acts, *_ = run(c, state, t + 300)
    assert acts == [] and state["floors"] == {} and state["asks"][_key(HIDE)]["deadline"] == t + 300 + 900


def test_an_accept_clears_the_floor_and_a_refused_one_keeps_it():
    for extra, cleared in (([], True), ([OTHER], False)):
        state, c = new_state(), conn([TRIG])
        run(c, state)
        c.findings = [NOTICE]
        run(c, state, 1e6 + 300)
        state["asks"][_key(NOTICE)]["answer"] = "accept"
        c.findings = [NOTICE, *extra]
        run(c, state, 1e6 + 600)
        assert ("mail" not in state["floors"]) == cleared


def test_a_cooling_account_drops_its_questions_and_asks_again_after_the_cooldown():
    from panic.guard import COOLDOWN_S
    state, c = new_state(), conn([TRIG])
    run(c, state)
    state["pressed"]["mail"] = 1e6 + 10  # pressed as downstream of another account
    run(c, state, 1e6 + 20)
    assert state["asks"] == {}
    t = 1e6 + 10 + COOLDOWN_S + 1
    _, acts, asked, _ = run(c, state, t)
    assert acts == [] and len(asked) == 1 and state["asks"][_key(TRIG)]["deadline"] == t + 900


def test_a_rehearsed_risky_change_leaves_no_floor():
    state, c = new_state(), conn([TRIG])
    run(c, state)
    c.findings = []  # `panic rehearse` made it the baseline
    run(c, state, 1e6 + 300, base={"forward": ["r"]})
    assert state["floors"] == {}
    c.findings = [HIDE]
    _, acts, asked, _ = run(c, state, 1e6 + 3900, base={"forward": ["r"]})
    assert acts == [] and len(asked) == 1 and state["asks"][_key(HIDE)]["deadline"] == 1e6 + 3900 + 900


def test_an_overdue_returning_change_prints_no_ask_line():
    state, c = new_state(), conn([TRIG])
    run(c, state)
    c.findings = []
    run(c, state, 1e6 + 300)
    c.findings = [TRIG]
    lines, acts, asked, _ = run(c, state, 1e6 + 1200)
    assert acts == [["mail"]] and asked == [] and not any(x.startswith("ask ") for x in lines)
