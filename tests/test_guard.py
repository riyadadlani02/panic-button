from fake import FakeConnector

from panic.guard import COOLDOWN_S, guard_once, new_state
from panic.model import Account, Finding, Severity

NOTICE = Finding("mail", "changed", Severity.NOTICE, "x", ("a",))
TRIG = Finding("mail", "rule_forwards_outside", Severity.TRIGGER, "x", ("r",))


class Flaky(FakeConnector):
    """Returns `findings` on the first read only."""
    def __init__(self):
        super().__init__()
        self.reads = 0

    def signals(self, account, snapshot, baseline):
        self.reads += 1
        return self.findings if self.reads == 1 else []


class Counting(FakeConnector):
    def __init__(self):
        super().__init__()
        self.snaps = 0

    def snapshot(self, account):
        self.snaps += 1
        return {}


class SecondReadFails(FakeConnector):
    def __init__(self):
        super().__init__()
        self.snaps = 0

    def snapshot(self, account):
        self.snaps += 1
        if self.snaps > 1:
            raise RuntimeError("down")
        return {}


class Broken(FakeConnector):
    def snapshot(self, account):
        raise RuntimeError("down")


def run(accounts=None, edges=(), conns=None, state=None, mode="press", released=(), now=lambda: 1e6,
        dry_run=False, baselines=None):
    accounts = accounts or [Account("mail", "fake")]
    conns = conns if conns is not None else {a.id: FakeConnector() for a in accounts}
    state = state if state is not None else new_state()
    acts, notes, saves = [], [], []
    lines = guard_once(accounts, list(edges), conns, baselines if baselines is not None else {a.id: {} for a in accounts},
                       set(released), state, mode, lambda t, f: acts.append((t, f)), notes.append,
                       lambda: saves.append(dict(state["pressed"])), now, dry_run)
    return lines, acts, notes, saves, state


def conn(findings=(), events=()):
    c = FakeConnector()
    c.findings, c.event_findings = list(findings), list(events)
    return c


def test_notice_is_reported_once():
    state, c = new_state(), {"mail": conn([NOTICE])}
    _, acts, n1, *_ = run(conns=c, state=state)
    _, acts2, n2, *_ = run(conns=c, state=state)
    assert len(n1) + len(n2) == 1 and not acts and not acts2


def test_trigger_presses_account_and_downstream_root_first():
    accts = [Account("bank", "fake"), Account("mail", "fake")]
    _, acts, *_ = run(accts, [("mail", "bank")], {"mail": conn([TRIG]), "bank": conn()})
    assert [t for t, _ in acts] == [["mail", "bank"]]


def test_upstream_is_not_pressed():
    t = Finding("bank", "key_added", Severity.TRIGGER, "x")
    accts = [Account("mail", "fake"), Account("bank", "fake")]
    _, acts, *_ = run(accts, [("mail", "bank")], {"mail": conn(), "bank": conn([t])})
    assert [t for t, _ in acts] == [["bank"]]


def test_protected_and_released_downstream_are_left_out():
    accts = [Account("mail", "fake"), Account("bank", "fake", protected=True), Account("social", "fake")]
    _, acts, *_ = run(accts, [("mail", "bank"), ("mail", "social")],
                      {"mail": conn([TRIG]), "bank": conn(), "social": conn()}, released={"social"})
    assert [t for t, _ in acts] == [["mail"]]


def test_trigger_that_vanishes_on_second_read_is_dropped():
    c = Flaky()
    c.findings = [TRIG]
    _, acts, notes, *_ = run(conns={"mail": c})
    assert not acts and not notes


def test_event_trigger_is_not_reread():
    c = Counting()
    c.event_findings = [TRIG]
    _, acts, *_ = run(conns={"mail": c})
    assert c.snaps == 1 and len(acts) == 1


def test_cooldown_blocks_a_second_press():
    state, c, t = new_state(), {"mail": conn([TRIG])}, [1e6]
    run(conns=c, state=state, now=lambda: t[0])
    t[0] += 3600
    lines, acts, *_ = run(conns=c, state=state, now=lambda: t[0])
    assert not acts and any("already handling" in ln for ln in lines)
    t[0] += COOLDOWN_S
    assert len(run(conns=c, state=state, now=lambda: t[0])[1]) == 1


def test_state_is_saved_before_acting():
    state, saved, at_act = new_state(), [], []
    guard_once([Account("mail", "fake")], [], {"mail": conn([TRIG])}, {"mail": {}}, set(), state, "press",
               lambda t, f: at_act.append(list(saved)), lambda f: None,
               lambda: saved.append(dict(state["pressed"])), lambda: 1e6)
    assert at_act == [[{"mail": 1e6}]]


def test_unreadable_account_is_a_notice_not_a_trigger():
    _, acts, notes, *_ = run(conns={"mail": Broken()})
    assert not acts and [n.code for n in notes] == ["unreadable"] and notes[0].severity == Severity.NOTICE


def test_missing_baseline_is_unreadable_not_a_crash():
    _, acts, notes, *_ = run(conns={"mail": conn([TRIG])}, baselines={})
    assert not acts and [n.code for n in notes] == ["unreadable"]


def test_alert_mode_never_acts():
    _, acts, notes, saves, _ = run(conns={"mail": conn([TRIG])}, mode="alert")
    assert not acts and not saves and len(notes) == 1


def test_dry_run_changes_nothing():
    c = {"mail": conn([NOTICE, TRIG], [])}
    lines, acts, notes, saves, state = run(conns=c, dry_run=True)
    assert state == new_state() and not acts and not saves and not notes
    assert any(ln.startswith("would") for ln in lines)


def test_heartbeat_line():
    lines, *_ = run(conns={"mail": conn()}, now=lambda: 0)
    assert lines[-1] == "00:00:00 read 1 accounts, 0 findings"


def test_failed_confirming_read_drops_triggers_with_unreadable_notice():
    c = SecondReadFails()
    c.findings = [TRIG]
    _, acts, notes, *_ = run(conns={"mail": c})
    assert not acts and [n.code for n in notes] == ["unreadable"]


def test_persistent_trigger_in_alert_mode_notifies_once_but_returns_line_each_pass():
    state, c = new_state(), {"mail": conn([TRIG])}
    l1, _, n1, *_ = run(conns=c, state=state, mode="alert")
    l2, _, n2, *_ = run(conns=c, state=state, mode="alert")
    assert len(n1) + len(n2) == 1
    assert sum("rule_forwards" in ln or TRIG.text in ln for ln in l1 + l2) == 2


def test_trigger_in_cooldown_does_not_notify_again():
    state, c, t = new_state(), {"mail": conn([TRIG])}, [10.0]
    _, _, n1, *_ = run(conns=c, state=state, now=lambda: t[0])
    t[0] += 300
    _, acts, n2, *_ = run(conns=c, state=state, now=lambda: t[0])
    assert len(n1) == 1 and not n2 and not acts


def test_first_press_works_with_small_now():
    _, acts, *_ = run(conns={"mail": conn([TRIG])}, now=lambda: 10)
    assert len(acts) == 1
