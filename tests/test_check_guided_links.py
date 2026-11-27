import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("check_guided_links", Path(__file__).parent.parent / "scripts" / "check-guided-links.py")
chk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(chk)

ENTRY = {"links": {"freeze_card": "https://www.bank.co.uk/freeze", "password": "https://login.bank.co.uk/pw"}}


def fake(table):
    def fetch(url):
        r = table[url]
        if isinstance(r, Exception):
            raise r
        return r
    return fetch


def test_verified_when_all_2xx_on_own_domain_even_after_redirect():
    ok, problems = chk.check_entry(ENTRY, fake({"https://www.bank.co.uk/freeze": (200, "https://www.bank.co.uk/freeze"),
                                                "https://login.bank.co.uk/pw": (200, "https://secure.bank.co.uk/pw")}))
    assert ok and problems == []


def test_not_verified_on_4xx_5xx_error_or_off_domain():
    good = (200, "https://www.bank.co.uk/freeze")
    for bad in [(404, "https://login.bank.co.uk/pw"), (503, "https://login.bank.co.uk/pw"), OSError("dns"),
                (200, "https://evilbank.co.uk/pw"), (200, "https://bank.com/pw"), (200, "https://co.uk/pw")]:
        ok, problems = chk.check_entry(ENTRY, fake({"https://www.bank.co.uk/freeze": good, "https://login.bank.co.uk/pw": bad}))
        assert not ok and len(problems) == 1, bad
