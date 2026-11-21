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


@pytest.mark.parametrize("url", [
    "https://s.test/\x1b[2Jx", "https://s.test/a b", "https://s.test/a\nb", "https://", "https:///path",
    "https://www.amazon.com@evil.test/", "http://s.test/", "javascript:alert(1)", "", "https://s.test/\x07",
])
def test_invalid_links_rejected(url):
    from panic.guided import valid_link
    assert not valid_link(url)


def test_valid_link_accepts_plain_https():
    from panic.guided import valid_link
    assert valid_link("https://x.com/settings/password?a=1")


def test_custom_entry_with_bad_link_raises_naming_key_and_kind_not_url():
    bad = {"shop": {"name": "S", "verified": True, "links": {"apps": "https://a@evil.test/secret"}}}
    with pytest.raises(ValueError) as e:
        Guided(bad)
    assert "shop" in str(e.value) and "apps" in str(e.value) and "evil.test" not in str(e.value)
