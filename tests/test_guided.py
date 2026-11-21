import pytest

from panic.guided import Guided
from panic.model import Account, Phase, Tier

ACC = Account("amazon:me@x.test", "guided")
FULL = {"name": "Shop", "verified": True, "links": {k: f"https://s.test/{k}" for k in
        ("password", "sign_out", "recovery", "devices", "two_factor", "apps")}}


def test_catalogue_order_phases_and_tier():
    steps = Guided({"amazon": FULL}).catalog(ACC)
    assert [s.action for s in steps] == ["sign_out", "devices", "apps", "two_factor", "recovery", "password"]
    assert steps[0].phase is Phase.FREEZE and steps[-1].phase is Phase.PURGE
    assert all(s.tier is Tier.GUIDED and s.account == ACC.id for s in steps)
    assert steps[0].title == "Shop: sign out everywhere" and steps[0].link == "https://s.test/sign_out"


def test_unverified_suffix_and_missing_links_skipped():
    entry = {"name": "Shop", "verified": False, "links": {"password": "https://s.test/p"}}
    (step,) = Guided({"amazon": entry}).catalog(ACC)
    assert step.title == "Shop: change the password (link not verified)"


def test_custom_overrides_shipped_entry():
    steps = Guided({"amazon": FULL}).catalog(ACC)
    assert "(link not verified)" not in steps[0].title  # shipped Amazon is unverified, custom replaced it


def test_shipped_catalogue_is_https_and_unverified():
    from panic.guided import load_services
    for key, e in load_services().items():
        assert e["verified"] is False and e["links"], key
        assert all(u.startswith("https://") for u in e["links"].values()), key
    assert Guided().catalog(ACC)[0].title.startswith("Amazon: ")


def test_unknown_key_raises():
    with pytest.raises(KeyError):
        Guided({}).catalog(Account("nope:me", "guided"))


def test_nothing_to_read_or_run():
    g = Guided()
    assert g.snapshot(ACC) == {} and not hasattr(g, "signals") and not hasattr(g, "events")
    step = g.catalog(ACC)[0]
    assert g.check(step, {}) is None
    with pytest.raises(NotImplementedError):
        g.run(step, {})
