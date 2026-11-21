import json

import pytest

from panic.graph_mail import delete_rules_outside, pages, rule_code, rules
from panic.http import ApiError

INBOX = "/users/a@corp.test/mailFolders/inbox/messageRules"


class FakeApi:
    """Fake Api: Graph responses by path or absolute URL; deletes drop the item unless its id is stuck."""

    def __init__(self, data=None):
        self.data, self.sent, self.deleted, self.stuck, self.reads = data or {}, [], [], set(), []

    def get(self, path, params=None):
        self.reads.append(path)
        v = self.data[path]
        if isinstance(v, Exception):
            raise v
        return v

    def send(self, method, path, body=None):
        self.sent.append((method, path, body))
        if method == "PATCH" and isinstance(self.data.get(path), dict):
            self.data[path].update(body)

    def delete(self, path, gone_ok=True):
        base, _, ident = path.rpartition("/")
        self.deleted.append(path)
        if ident in self.stuck:
            return
        for key in [base] if base in self.data else list(self.data):  # a top-level delete drops it wherever listed
            if isinstance(self.data[key], dict) and "value" in self.data[key]:
                self.data[key]["value"] = [x for x in self.data[key]["value"] if x.get("id") != ident]


def rule(i="1", name="r", actions=None, conditions=None, enabled=True):
    return {"id": i, "displayName": name, "isEnabled": enabled, "conditions": conditions or {},
            "actions": actions or {}, "sequence": 1}


def canon(r):
    return json.dumps({k: r[k] for k in ("displayName", "isEnabled", "conditions", "actions")}, sort_keys=True)


def to(addr):
    return {"emailAddress": {"address": addr}}


def test_pages_follows_odata_next_link():
    nxt = "https://graph.microsoft.com/v1.0/users?$skiptoken=x"
    api = FakeApi({"/users": {"value": [1], "@odata.nextLink": nxt}, nxt: {"value": [2]}})
    assert pages(api, "/users") == [1, 2]


def test_rules_are_canonical_json_without_id_or_sequence():
    r = rule("9", "fwd", {"redirectTo": [to("x@evil.test")]})
    api = FakeApi({INBOX: {"value": [r]}})
    assert rules(api, "a@corp.test") == [canon(r)]


def test_me_uses_the_me_path():
    api = FakeApi({"/me/mailFolders/inbox/messageRules": {"value": []}})
    assert rules(api, "me") == []


def test_delete_keeps_baseline_rules_and_removes_the_rest():
    keep, bad = rule("1", "keep"), rule("2", "bad")
    api = FakeApi({INBOX: {"value": [keep, bad]}})
    delete_rules_outside(api, "a@corp.test", [canon(keep)])
    assert api.deleted == [f"{INBOX}/2"] and rules(api, "a@corp.test") == [canon(keep)]


def test_delete_raises_when_a_rule_survives():
    api = FakeApi({INBOX: {"value": [rule("2", "readonly")]}})
    api.stuck = {"2"}
    with pytest.raises(RuntimeError) as e:
        delete_rules_outside(api, "a@corp.test", [])
    assert "readonly" not in str(e.value)


def test_a_failed_read_deletes_nothing():
    api = FakeApi({INBOX: ApiError(429, "")})
    with pytest.raises(ApiError):
        delete_rules_outside(api, "a@corp.test", [])
    assert api.deleted == []


@pytest.mark.parametrize("key", ["forwardTo", "forwardAsAttachmentTo", "redirectTo"])
def test_forward_outside_own_domains(key):
    out, own = canon(rule(actions={key: [to("x@evil.test")]})), canon(rule(actions={key: [to("B@Corp.test")]}))
    assert rule_code(out, {"corp.test"}) == "rule_forwards_outside"
    assert rule_code(own, {"corp.test"}) is None
    assert rule_code(own, None) == "rule_forwards_outside"


def test_hiding_rules():
    for actions in ({"delete": True}, {"permanentDelete": True}, {"moveToFolder": "f", "markAsRead": True}):
        assert rule_code(canon(rule(actions=actions)), set()) == "rule_hides_mail"
    assert rule_code(canon(rule(actions={"moveToFolder": "f"})), set()) is None
    assert rule_code("not json", set()) == "rule_hides_mail"
