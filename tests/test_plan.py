from fake import FakeConnector

from panic.executor import compile_plan, outside_baseline
from panic.model import Account, Phase, Step, Tier

ACCTS = [Account("bank", "fake"), Account("mail", "fake"), Account("boss", "fake", protected=True), Account("old", "nowhere")]


def test_plan_is_root_first_freeze_before_purge():
    plan = compile_plan(ACCTS, [("mail", "bank")], {"fake": FakeConnector(steps=[
        Step("", "purge_x", Phase.PURGE, Tier.API, "x"), Step("", "freeze_x", Phase.FREEZE, Tier.API, "x")])})
    assert [(s.account, s.action) for s in plan] == [
        ("mail", "freeze_x"), ("bank", "freeze_x"), ("mail", "purge_x"), ("bank", "purge_x")]


def test_protected_and_unsupported_accounts_get_no_steps():
    plan = compile_plan(ACCTS, [], {"fake": FakeConnector(steps=[Step("", "f", Phase.FREEZE, Tier.API, "f")])})
    assert {s.account for s in plan} == {"bank", "mail"}


def test_outside_baseline():
    assert outside_baseline({"filters": ["a"], "delegates": []}, {"filters": ["a", "b"], "delegates": ["x"], "new": ["n"]}) \
        == ["delegates: x", "filters: b", "new: n"]
