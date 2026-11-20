import threading
import time

import pytest
from fake import FakeConnector

from panic.executor import compile_plan, press
from panic.model import Account, Evidence, Phase, Status, Step, Tier


def mk(**kw):
    steps = [Step("", "freeze", Phase.FREEZE, Tier.API, "Freeze"),
             Step("", "signout", Phase.FREEZE, Tier.API, "Sign out"),
             Step("", "purge", Phase.PURGE, Tier.API, "Purge"),
             Step("", "guided", Phase.PURGE, Tier.GUIDED, "Guided")]
    return FakeConnector(**{"steps": steps, "no_readback": {"signout", "guided"}, **kw})


def by(out, account, action):
    return next(r for r in out.results if r.step.account == account and r.step.action == action)


A = [Account("mail", "fake"), Account("bank", "fake")]; E = [("mail", "bank")]
def run(c, confirm=lambda s: True, **kw):
    return press(compile_plan(A, E, {"fake": c}), A, E, {"fake": c}, {}, confirm, lambda e: None, **kw)

def test_evidence_levels():
    out = run(mk())
    assert by(out, "mail", "freeze").evidence is Evidence.VERIFIED
    assert by(out, "mail", "signout").evidence is Evidence.ACCEPTED
    assert by(out, "mail", "guided").evidence is Evidence.OWNER_CONFIRMED
    assert all(r.status is Status.LOCKED for r in out.results)

def test_unconfirmed_guided_step_needs_you():
    assert by(run(mk(), confirm=lambda s: False), "mail", "guided").status is Status.NEEDS_YOU

def test_guided_step_marked_done_but_readback_disagrees():
    assert by(run(mk(no_readback={"signout"})), "mail", "guided").status is Status.NEEDS_YOU

def test_failure_is_isolated_and_marks_dependents():
    out = run(mk(fail={"mail/freeze"}))
    assert by(out, "mail", "freeze").status is Status.STILL_OPEN and "boom" in by(out, "mail", "freeze").detail
    assert by(out, "bank", "freeze").status is Status.LOCKED
    assert by(out, "bank", "reopenable").status is Status.STILL_OPEN and "mail" in by(out, "bank", "reopenable").detail

def test_run_succeeds_but_readback_says_no():
    c = mk(); c.run = lambda step, baseline: c.ran.append(step.action)      # never flips state
    assert by(run(c), "mail", "freeze").status is Status.STILL_OPEN

def test_root_without_connector_marks_dependents():
    accts = [Account("outlook", "nowhere"), Account("bank", "fake")]; c = mk()
    out = press(compile_plan(accts, [("outlook", "bank")], {"fake": c}), accts, [("outlook", "bank")], {"fake": c}, {}, lambda s: True, lambda e: None)
    assert "outlook" in by(out, "bank", "reopenable").detail

def test_dead_credential_fails_every_step_for_that_account_only():
    out = run(mk(fail={"mail/freeze", "mail/signout", "mail/purge"}))
    assert {r.status for r in out.results if r.step.account == "mail" and r.step.tier is Tier.API} == {Status.STILL_OPEN}
    assert by(out, "bank", "purge").status is Status.LOCKED

def test_pressing_twice_is_safe():
    c = mk(); first = run(c); second = run(c)
    assert [(r.step.action, r.status) for r in first.results] == [(r.step.action, r.status) for r in second.results]

def test_dry_run_changes_nothing():
    c = mk(); c.snap = {"filters": ["evil"]}
    out = run(c, dry_run=True, confirm=lambda s: pytest.fail("asked during dry run"))
    assert c.ran == [] and out.touched["mail"] == ["filters: evil"]

def test_touched_and_log():
    c = mk(); c.snap = {"filters": ["evil"]}; seen = []
    out = press(compile_plan(A, E, {"fake": c}), A, E, {"fake": c}, {"mail": {"filters": []}, "bank": {"filters": ["evil"]}}, lambda s: True, seen.append)
    assert out.touched == {"mail": ["filters: evil"], "bank": []}
    assert len(seen) == len(out.results) and {"account", "action", "status", "evidence"} <= seen[0].keys()

def test_guided_steps_are_asked_roots_first_after_api_steps():
    asked = []; c = mk()
    run(c, confirm=lambda s: asked.append((s.account, len(c.ran))) or True)
    assert asked == [("mail", 6), ("bank", 6)]

def test_interrupted_walkthrough_keeps_results():
    def ctrl_c(step): raise KeyboardInterrupt
    out = run(mk(), confirm=ctrl_c)
    for acct in ("mail", "bank"):
        g = by(out, acct, "guided")
        assert g.status is Status.NEEDS_YOU and g.detail == "not asked"
    assert by(out, "mail", "freeze").status is Status.LOCKED


def test_log_failure_keeps_results_and_appends_audit_result():
    n = []
    def bad_log(e):
        n.append(e)
        if len(n) == 2: raise OSError("disk full")
    c = mk()
    out = press(compile_plan(A, E, {"fake": c}), A, E, {"fake": c}, {}, lambda s: True, bad_log)
    assert len(n) == 2 and out.results[-1].step.action == "audit_log" and "disk full" in out.results[-1].detail
    assert out.results[-1].status is Status.STILL_OPEN
    assert all(r.status is Status.LOCKED for r in out.results[:-1]) and len(out.results) == 9

def test_non_bool_check_result_is_not_verified():
    c = mk(); c.check = lambda step, baseline: 1
    r = by(run(c), "mail", "freeze")
    assert r.status is Status.STILL_OPEN and "1" in r.detail

def _wait_until(pred, timeout=5):
    end = time.monotonic() + timeout
    while not pred() and time.monotonic() < end:
        time.sleep(0.005)
    assert pred()


def _interrupting(c, release=None):
    """mail/freeze raises Ctrl-C once bank's freeze steps have finished; bank/purge-phase never runs."""
    orig = c.run
    def run_(step, baseline):
        key = f"{step.account}/{step.action}"
        if key == "mail/freeze":
            _wait_until(lambda: {"bank/freeze"} | ({"bank/signout"} if release is None else set()) <= set(c.ran))
            time.sleep(0.1)  # let those workers publish their results
            raise KeyboardInterrupt
        if key == "bank/signout" and release is not None:
            release.wait(10)
        orig(step, baseline)
    c.run = run_


def test_interrupt_keeps_finished_results_and_marks_the_rest():
    c = mk(); _interrupting(c)
    out = run(c, confirm=lambda s: pytest.fail("asked after interrupt"))
    plan = compile_plan(A, E, {"fake": c})
    assert [(r.step.account, r.step.action) for r in out.results if r.step.action != "reopenable"] == [(s.account, s.action) for s in plan]
    assert by(out, "bank", "freeze").status is Status.LOCKED and by(out, "bank", "freeze").evidence is Evidence.VERIFIED
    assert by(out, "mail", "freeze").status is Status.STILL_OPEN and by(out, "mail", "freeze").detail == "interrupted"
    assert not [k for k in c.ran if k.endswith("/purge")]
    for acct in ("mail", "bank"):
        assert by(out, acct, "purge").detail == "interrupted"
        assert by(out, acct, "guided").status is Status.NEEDS_YOU and by(out, acct, "guided").detail == "not asked"


def test_interrupt_in_guided_check_keeps_earlier_results():
    c = mk(); orig = c.check
    def check(step, baseline):
        if step.action == "guided" and step.account == "bank": raise KeyboardInterrupt
        return orig(step, baseline)
    c.check = check
    out = run(c)
    assert by(out, "mail", "guided").status is Status.LOCKED
    g = by(out, "bank", "guided")
    assert g.status is Status.NEEDS_YOU and g.detail == "not asked"
    assert by(out, "bank", "freeze").status is Status.LOCKED


def test_press_returns_while_a_provider_call_is_still_blocked():
    c = mk(); release = threading.Event(); _interrupting(c, release)
    try:
        out = run(c, confirm=lambda s: pytest.fail("asked after interrupt"))
        assert not release.is_set() and by(out, "bank", "signout").detail == "interrupted"
    finally:
        release.set()

def test_protected_account_is_not_read_and_not_an_open_resetter():
    c = mk(); reads = []; c.snapshot = lambda a: reads.append(a.id) or {}
    accts = [Account("vault", "fake", protected=True), Account("bank", "fake")]
    out = press(compile_plan(accts, [("vault", "bank")], {"fake": c}), accts, [("vault", "bank")], {"fake": c}, {}, lambda s: True, lambda e: None)
    assert reads == ["bank"] and set(out.touched) == {"bank"}
    assert not [r for r in out.results if r.step.action == "reopenable"]

def test_check_that_raises_is_still_open_with_error_text():
    c = mk()
    def bad(step, baseline): raise RuntimeError("readback down")
    c.check = bad
    r = by(run(c), "mail", "freeze")
    assert r.status is Status.STILL_OPEN and "readback down" in r.detail

def test_snapshot_that_raises_is_unknown():
    c = mk()
    def bad(a): raise RuntimeError("no read")
    c.snapshot = bad
    assert run(c).touched["mail"] == ["unknown: could not read (no read)"]
