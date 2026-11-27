from fake import FakeConnector

from panic.guard import COOLDOWN_S, EVENT_OVERLAP_S, RENOTIFY_S, guard_once, load_state, new_state
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
        dry_run=False, baselines=None, act=None):
    accounts = accounts or [Account("mail", "fake")]
    conns = conns if conns is not None else {a.id: FakeConnector() for a in accounts}
    state = state if state is not None else new_state()
    acts, notes, saves = [], [], []
    lines = guard_once(accounts, list(edges), conns, baselines if baselines is not None else {a.id: {} for a in accounts},
                       set(released), state, mode, act or (lambda t, f: acts.append((t, f))), lambda f, extra: notes.append(f),
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
               lambda t, f: at_act.append(list(saved)), lambda f, extra: None,
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
    assert lines[-1] == "00:00:00 read 1 accounts, 0 findings, 0 skipped"


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


class EventsFail(FakeConnector):
    def __init__(self):
        super().__init__()
        self.since, self.fail = [], True

    def events(self, account, since):
        self.since.append(since)
        if self.fail:
            self.fail = False
            raise RuntimeError("down")
        return []


class RealSignature(FakeConnector):
    def events(self, account, since):
        assert isinstance(since, float)
        return []


def test_failed_events_read_keeps_the_cursor():
    c, state = EventsFail(), new_state()
    state["cursors"]["mail"] = 100.0
    _, _, notes, *_ = run(conns={"mail": c}, state=state, now=lambda: 500.0)
    assert [n.code for n in notes] == ["events_unreadable"] and state["cursors"]["mail"] == 100.0
    run(conns={"mail": c}, state=state, now=lambda: 900.0)
    assert c.since == [100.0 - EVENT_OVERLAP_S] * 2 and state["cursors"]["mail"] == 900.0


def test_events_receives_a_float_since():
    c = RealSignature()
    _, _, notes, *_ = run(conns={"mail": c}, now=lambda: 5.0)
    assert not notes
    run(conns={"mail": c}, now=lambda: 6.0)  # stored cursor path too


def test_heartbeat_counts_skipped_accounts():
    accts = [Account("mail", "fake"), Account("boss", "fake", protected=True), Account("away", "fake")]
    lines, *_ = run(accts, released={"away"}, now=lambda: 0)
    assert lines[-1] == "00:00:00 read 1 accounts, 0 findings, 2 skipped"


def test_unreadable_is_printed_each_pass_and_notified_again_after_renotify():
    state, c, t = new_state(), {"mail": Broken()}, [1e6]
    l1, _, n1, *_ = run(conns=c, state=state, now=lambda: t[0])
    t[0] += RENOTIFY_S - 1
    l2, _, n2, *_ = run(conns=c, state=state, now=lambda: t[0])
    t[0] += 2
    _, _, n3, *_ = run(conns=c, state=state, now=lambda: t[0])
    assert len(n1) == 1 and n2 == [] and len(n3) == 1
    assert any("could not be read" in ln for ln in l2)


def test_a_second_outage_after_a_good_read_notifies_again():
    state = new_state()
    run(conns={"mail": Broken()}, state=state)
    run(conns={"mail": conn()}, state=state)
    _, _, notes, *_ = run(conns={"mail": Broken()}, state=state)
    assert [n.code for n in notes] == ["unreadable"]


def test_a_second_events_outage_after_a_good_read_notifies_again():
    state, c = new_state(), EventsFail()
    run(conns={"mail": c}, state=state)
    run(conns={"mail": c}, state=state)
    c.fail = True
    _, _, notes, *_ = run(conns={"mail": c}, state=state)
    assert [n.code for n in notes] == ["events_unreadable"]


def test_a_trigger_that_goes_and_comes_back_in_alert_mode_notifies_again():
    state = new_state()
    _, _, n1, *_ = run(conns={"mail": conn([TRIG])}, state=state, mode="alert")
    run(conns={"mail": conn()}, state=state, mode="alert")
    _, _, n2, *_ = run(conns={"mail": conn([TRIG])}, state=state, mode="alert")
    assert len(n1) == len(n2) == 1


def test_a_notice_that_goes_and_comes_back_notifies_again():
    state = new_state()
    run(conns={"mail": conn([NOTICE])}, state=state)
    run(conns={"mail": conn()}, state=state)
    _, _, notes, *_ = run(conns={"mail": conn([NOTICE])}, state=state)
    assert notes == [NOTICE]


def test_an_old_list_shaped_state_loads():
    state = load_state({"seen": ["mail|unreadable|"], "cursors": {"mail": 5.0}, "pressed": {}})
    assert state["seen"] == {"mail|unreadable|": 0.0} and state["events_seen"] == {} and state["cursors"] == {"mail": 5.0}
    _, _, notes, *_ = run(conns={"mail": Broken()}, state=state)
    assert [n.code for n in notes] == ["unreadable"]  # migrated keys count as long ago


class Since(FakeConnector):
    def __init__(self):
        super().__init__()
        self.since = []

    def events(self, account, since):
        self.since.append(since)
        return self.event_findings


def test_events_are_read_with_an_overlap_from_the_start():
    c, state = Since(), new_state()
    run(conns={"mail": c}, state=state, now=lambda: 10000.0)
    run(conns={"mail": c}, state=state, now=lambda: 10300.0)
    assert c.since == [10000.0 - EVENT_OVERLAP_S, 10000.0 - EVENT_OVERLAP_S]


def test_an_event_already_seen_is_skipped_and_forgotten_after_two_days():
    ev = Finding("mail", "provider_flagged_login", Severity.TRIGGER, "x", ("e",), key="evt-1")
    c, state, t = Since(), new_state(), [1e6]
    c.event_findings = [ev]
    _, acts, *_ = run(conns={"mail": c}, state=state, mode="alert", now=lambda: t[0])
    t[0] += 300
    lines, *_ = run(conns={"mail": c}, state=state, mode="alert", now=lambda: t[0])
    assert "mail|evt-1" in state["events_seen"] and lines[-1].endswith("0 findings, 0 skipped")
    t[0] += 48 * 3600 + 1
    c.event_findings = []
    run(conns={"mail": c}, state=state, mode="alert", now=lambda: t[0])
    assert state["events_seen"] == {}


def test_an_event_without_a_key_is_never_taken_as_seen():
    ev = Finding("mail", "provider_flagged_login", Severity.TRIGGER, "x", ("e",))
    c, state = Since(), new_state()
    c.event_findings = [ev]
    run(conns={"mail": c}, state=state, mode="alert")
    lines, *_ = run(conns={"mail": c}, state=state, mode="alert")
    assert state["events_seen"] == {} and lines[-1].endswith("1 findings, 0 skipped")


def test_a_downstream_account_in_cooldown_is_not_pressed_again():
    accts = [Account("a", "fake"), Account("b", "fake"), Account("c", "fake")]
    edges = [("a", "b"), ("c", "b")]
    state, t = new_state(), [1e6]
    ta = Finding("a", "key_added", Severity.TRIGGER, "x")
    tc = Finding("c", "key_added", Severity.TRIGGER, "x")
    _, acts, *_ = run(accts, edges, {"a": conn([ta]), "b": conn(), "c": conn()}, state, now=lambda: t[0])
    t[0] += 3600
    _, acts2, *_ = run(accts, edges, {"a": conn(), "b": conn(), "c": conn([tc])}, state, now=lambda: t[0])
    assert [x for x, _ in acts] == [["a", "b"]] and [x for x, _ in acts2] == [["c"]]


def test_a_failed_press_says_so_while_in_cooldown():
    state, c, t = new_state(), {"mail": conn([TRIG])}, [1e6]
    run(conns=c, state=state, now=lambda: t[0], act=lambda targets, f: False)
    t[0] += 300
    lines, *_ = run(conns=c, state=state, now=lambda: t[0])
    assert any("automatic press failed" in ln and "panic press" in ln for ln in lines)
    assert not any("already handling" in ln for ln in lines)


def test_the_trigger_notification_says_what_the_guard_does():
    for mode, words in (("press", "Pressing"), ("contain", "contain it"), ("alert", "Alert only")):
        extras = []
        guard_once([Account("mail", "fake")], [], {"mail": conn([TRIG])}, {"mail": {}}, set(), new_state(), mode,
                   lambda t, f: None, lambda f, extra: extras.append(extra), lambda: None, lambda: 1e6)
        assert words in extras[0]


def test_also_check_is_only_added_to_triggers():
    accts = [Account("mail", "fake"), Account("bank", "fake")]
    n = Finding("bank", "new_access", Severity.NOTICE, "new access")
    t = Finding("bank", "key_added", Severity.TRIGGER, "key")
    lines, *_ = run(accts, [("mail", "bank")], {"mail": conn(), "bank": conn([n, t])}, mode="alert")
    assert [ln for ln in lines if "Also check: mail" in ln] == ["notify bank: key Also check: mail"]


def test_the_same_event_key_on_two_accounts_acts_on_both():
    accts = [Account("x", "fake"), Account("y", "fake")]
    conns = {}
    for a in ("x", "y"):
        conns[a] = Since()
        conns[a].event_findings = [Finding(a, "provider_flagged_login", Severity.TRIGGER, "f", ("anomaly",), key="e-1")]
    _, acts, *_ = run(accts, conns=conns)
    assert [t for t, _ in acts] == [["x"], ["y"]]


class Drifting(FakeConnector):
    """Real drift: a category missing from the baseline raises, as every connector does."""
    def signals(self, account, snapshot, baseline):
        from panic.signals import drift
        return drift(account.id, baseline, snapshot, lambda c, i: "key_added")


def test_a_category_missing_from_an_old_baseline_is_adopted_once_and_never_overrides_a_known_one():
    c = Drifting()
    c.snap = {"old": ["a", "b"], "new": ["n"]}
    baselines, state, acts, notes, extended = {"mail": {"old": ["a"]}}, new_state(), [], [], []
    for _ in range(2):
        guard_once([Account("mail", "fake")], [], {"mail": c}, baselines, set(), state, "alert",
                   lambda t, f: acts.append(t), lambda f, extra: notes.append(f), lambda: None, lambda: 1e6,
                   extend=lambda i, cats: extended.append((i, cats)))
    assert extended == [("mail", {"new": ["n"]})] and baselines["mail"] == {"old": ["a"], "new": ["n"]}
    assert [(n.code, n.items) for n in notes] == [("key_added", ("old: b",))]  # "old" was never adopted


def test_a_dry_run_reads_with_the_adopted_category_but_saves_nothing():
    c = Drifting()
    c.snap = {"old": ["a"], "new": ["n"]}
    baselines, extended = {"mail": {"old": ["a"]}}, []
    lines = guard_once([Account("mail", "fake")], [], {"mail": c}, baselines, set(), new_state(), "press",
                       lambda t, f: None, lambda f, extra: None, lambda: None, lambda: 1e6, dry_run=True,
                       extend=lambda i, cats: extended.append(i))
    assert extended == [] and baselines["mail"] == {"old": ["a"]} and "0 findings" in lines[-1]
