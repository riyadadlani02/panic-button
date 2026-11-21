import sys
import types

import pytest
from test_graph_mail import FakeApi, canon, rule, to

from panic.microsoft_personal import MicrosoftPersonal
from panic.model import Account, Phase, Severity, Step, Tier

ME = "/me/mailFolders/inbox/messageRules"
ACCT = Account("me@outlook.com", "microsoft_personal")


def conn(rules_, **kw):
    return MicrosoftPersonal({ACCT.id: {"client_id": "c", "cache": "x"}},
                             api=FakeApi({ME: {"value": rules_}}), **kw)


def step(action):
    return Step(ACCT.id, action, Phase.PURGE, Tier.API, "t")


def test_snapshot_is_the_inbox_rules():
    r = rule("1", "a")
    assert conn([r]).snapshot(ACCT) == {"inbox_rules": [canon(r)]}


def test_forwarding_to_any_address_triggers_and_a_plain_move_is_changed():
    fwd = rule("1", "f", {"forwardTo": [to("me@outlook.com")]})
    move = rule("2", "m", {"moveToFolder": "archive"})
    found = {f.code: f for f in conn([]).signals(ACCT, {"inbox_rules": [canon(fwd), canon(move)]}, {"inbox_rules": []})}
    assert found["rule_forwards_outside"].severity is Severity.TRIGGER
    assert found["changed"].severity is Severity.NOTICE and "rule_hides_mail" not in found


def test_run_deletes_only_rules_outside_the_baseline():
    keep, bad = rule("1", "keep"), rule("2", "bad")
    c = conn([keep, bad])
    c.run(step("inbox_rules"), {"inbox_rules": [canon(keep)]})
    assert c._api_for(ACCT.id).deleted == [f"{ME}/2"]
    assert c.check(step("inbox_rules"), {"inbox_rules": [canon(keep)]}) is True


def test_run_without_a_baseline_fails_closed():
    with pytest.raises(KeyError, match="no baseline recorded for inbox_rules"):
        conn([rule("1")]).run(step("inbox_rules"), {})


def test_guided_steps_are_marked_unverified_and_never_run():
    steps = conn([]).catalog(ACCT)
    guided = [s for s in steps if s.tier is Tier.GUIDED]
    assert [s.action for s in steps][-1] == "password" and "--reconnect" in steps[-1].title
    assert guided and all(s.title.endswith(" (link not verified)") and s.link.startswith("https://") for s in guided)
    with pytest.raises(NotImplementedError):
        conn([]).run(guided[0], {})


def fake_msal(monkeypatch, silent, rotate=False):
    class Cache:
        has_state_changed = False

        def deserialize(self, s):
            self.s = s

        def serialize(self):
            return "rotated"

    class App:
        def __init__(self, client_id, authority=None, token_cache=None):
            self.cache = token_cache

        def get_accounts(self):
            return [{"username": ACCT.id}]

        def acquire_token_silent(self, scopes, account=None):
            self.cache.has_state_changed = rotate
            return silent

    monkeypatch.setitem(sys.modules, "msal", types.SimpleNamespace(
        PublicClientApplication=App, SerializableTokenCache=Cache))


def test_expired_sign_in_says_how_to_reconnect(monkeypatch):
    fake_msal(monkeypatch, None)
    c = MicrosoftPersonal({ACCT.id: {"client_id": "c", "cache": "x"}})
    with pytest.raises(RuntimeError, match=r"panic arm --microsoft-personal <email> --reconnect"):
        c._token(ACCT.id)


def test_a_rotated_cache_is_handed_back_once_and_reused(monkeypatch):
    fake_msal(monkeypatch, {"access_token": "T"}, rotate=True)
    saved = []
    c = MicrosoftPersonal({ACCT.id: {"client_id": "c", "cache": "x"}}, on_refresh=lambda a, t: saved.append((a, t)))
    assert c._token(ACCT.id) == "T"
    assert saved == [(ACCT.id, {"client_id": "c", "cache": "rotated"})]
    assert c._tokens[ACCT.id]["cache"] == "rotated"


def test_an_unchanged_cache_is_not_saved(monkeypatch):
    fake_msal(monkeypatch, {"access_token": "T"})
    saved = []
    MicrosoftPersonal({ACCT.id: {"client_id": "c", "cache": "x"}}, on_refresh=lambda *a: saved.append(a))._token(ACCT.id)
    assert saved == []
