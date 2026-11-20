import pytest
from fake import FakeConnector

from panic.executor import watch, watch_once
from panic.model import Account, Phase, Result, Status, Step, Tier, WatchPolicy

A = [Account("mail", "fake")]


def locked(action, policy):
    return Result(Step("mail", action, Phase.FREEZE, Tier.API, action, watch=policy), Status.LOCKED)


@pytest.fixture
def c():
    c = FakeConnector()
    c.state = {f"mail/{a}": True for a in ("fwd", "apps", "suspend")}
    return c


@pytest.fixture
def seen():
    return []


def test_reapply_puts_setting_back(c, seen):
    c.state["mail/fwd"] = False
    lines = watch_once([locked("fwd", WatchPolicy.REAPPLY)], {"fake": c}, A, {}, set(), seen.append)
    assert c.state["mail/fwd"] is True and "mail/fwd" in c.ran and len(lines) == 1 and seen[0]["event"] == "reapplied"
    assert {"event", "account", "action", "detail"} <= seen[0].keys()


def test_report_policy_never_runs(c, seen):
    c.state["mail/apps"] = False
    lines = watch_once([locked("apps", WatchPolicy.REPORT)], {"fake": c}, A, {}, set(), seen.append)
    assert c.ran == [] and seen[0]["event"] == "changed" and len(lines) == 1


def test_released_account_is_not_resuspended(c, seen):
    c.state["mail/suspend"] = False
    assert watch_once([locked("suspend", WatchPolicy.REAPPLY)], {"fake": c}, A, {}, {"mail"}, seen.append) == []


def test_quiet_when_nothing_changed_and_skips_non_locked(c, seen):
    open_one = Result(Step("mail", "x", Phase.FREEZE, Tier.API, "x", watch=WatchPolicy.REAPPLY), Status.STILL_OPEN)
    assert watch_once([locked("fwd", WatchPolicy.REAPPLY), open_one], {"fake": c}, A, {}, set(), seen.append) == [] and seen == []


def test_a_failing_check_is_reported_not_raised(c, seen):
    c.check = lambda step, baseline: (_ for _ in ()).throw(RuntimeError("net down"))
    assert "net down" in watch_once([locked("fwd", WatchPolicy.REAPPLY)], {"fake": c}, A, {}, set(), seen.append)[0]
    assert seen[0]["event"] == "check_failed"


def test_loop_stops_after_window():
    clock = iter(range(0, 100000, 3600)); sleeps = []
    watch([], {}, [], {}, set, lambda e: None, hours=2, interval_s=3600, sleep=sleeps.append, now=lambda: next(clock))
    assert sleeps == [3600]


def test_failed_reapply_is_reported(c, seen):
    c.state["mail/fwd"] = False
    c.run = lambda step, baseline: c.ran.append("x")  # never flips state
    lines = watch_once([locked("fwd", WatchPolicy.REAPPLY)], {"fake": c}, A, {}, set(), seen.append)
    assert "still open after reapply" in lines[0] and seen[0]["event"] == "reapply_failed"


def test_reapply_that_raises_is_reported(c, seen):
    c.state["mail/fwd"] = False
    c.fail = {"mail/fwd"}
    lines = watch_once([locked("fwd", WatchPolicy.REAPPLY)], {"fake": c}, A, {}, set(), seen.append)
    assert "boom" in lines[0] and seen[0]["event"] == "reapply_failed" and "boom" in seen[0]["detail"]


def test_non_bool_check_is_reported_and_never_runs(c, seen):
    c.check = lambda step, baseline: 1
    lines = watch_once([locked("fwd", WatchPolicy.REAPPLY)], {"fake": c}, A, {}, set(), seen.append)
    assert c.ran == [] and "1" in lines[0] and seen[0]["event"] == "check_failed"


def test_none_check_is_skipped(c, seen):
    c.no_readback = {"fwd"}
    assert watch_once([locked("fwd", WatchPolicy.REAPPLY)], {"fake": c}, A, {}, set(), seen.append) == [] and seen == []


def test_raising_log_does_not_stop_the_pass(c):
    c.state["mail/fwd"] = c.state["mail/apps"] = False
    def bad(e): raise OSError("disk full")
    lines = watch_once([locked("fwd", WatchPolicy.REAPPLY), locked("apps", WatchPolicy.REPORT)],
                       {"fake": c}, A, {}, set(), bad)
    assert c.state["mail/fwd"] is True and len(lines) == 3
    assert [l for l in lines if "could not write the audit log: disk full" in l] != [] and sum("audit log" in l for l in lines) == 1


def test_unknown_provider_or_account_is_skipped(c, seen):
    c.state["mail/fwd"] = False
    r = [locked("fwd", WatchPolicy.REAPPLY)]
    assert watch_once(r, {}, A, {}, set(), seen.append) == []
    assert watch_once(r, {"fake": c}, [], {}, set(), seen.append) == [] and c.ran == []


def test_released_is_re_read_each_pass(c, seen):
    c.state["mail/suspend"] = False
    clock = iter(range(0, 100000, 1)); sets = iter([{"mail"}, set()])
    watch([locked("suspend", WatchPolicy.REAPPLY)], {"fake": c}, A, {}, lambda: next(sets), seen.append,
          hours=3 / 3600, interval_s=0, sleep=lambda s: None, now=lambda: next(clock))
    assert c.ran == ["mail/suspend"] and len(seen) == 1


def test_baseline_is_passed_to_check_and_run(c):
    got = []
    c.state["mail/fwd"] = False
    orig = c.check
    c.check = lambda step, baseline: got.append(baseline) or orig(step, baseline)
    watch_once([locked("fwd", WatchPolicy.REAPPLY)], {"fake": c}, A, {"mail": {"k": ["v"]}}, set(), lambda e: None)
    assert got[0] == {"k": ["v"]}


def test_reapply_logs_what_it_removed(c, seen):
    c.state["mail/fwd"] = False
    c.snapshot = lambda a: {"filters": ["keep"]} if c.ran else {"filters": ["keep", "evil"]}
    watch_once([locked("fwd", WatchPolicy.REAPPLY)], {"fake": c}, A, {}, set(), seen.append)
    assert seen[0]["event"] == "reapplied" and "filters: evil" in seen[0]["detail"] and "keep" not in seen[0]["detail"]


def test_reapply_with_unreadable_snapshot_says_unknown(c, seen):
    c.state["mail/fwd"] = False
    c.snapshot = lambda a: (_ for _ in ()).throw(RuntimeError("no read"))
    watch_once([locked("fwd", WatchPolicy.REAPPLY)], {"fake": c}, A, {}, set(), seen.append)
    assert seen[0]["event"] == "reapplied" and "unknown" in seen[0]["detail"] and "no read" in seen[0]["detail"]
