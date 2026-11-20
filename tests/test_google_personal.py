import json
from unittest.mock import MagicMock

import pytest

from panic import google_personal
from panic.google_personal import Personal
from panic.model import Account

ACCT = Account("me@example.com", "google_personal")
TOKEN = {"client_id": "i", "client_secret": "s", "refresh_token": "r"}
F1 = {"criteria": {"from": "a@x"}, "action": {"addLabelIds": ["L"]}}
CANON_F1 = json.dumps(F1, sort_keys=True)


def make(filters=(), fwd=None, imap=False, pop="disabled"):
    svc = MagicMock()
    st = svc.users().settings()
    st.filters().list().execute.return_value = {"filter": list(filters)}
    st.getAutoForwarding().execute.return_value = fwd or {"enabled": False}
    st.getImap().execute.return_value = {"enabled": imap}
    st.getPop().execute.return_value = {"accessWindow": pop}
    return Personal({ACCT.id: TOKEN}, build=lambda *a, **k: svc), svc


def step(conn, action):
    return next(s for s in conn.catalog(ACCT) if s.action == action)


def test_snapshot_shape():
    conn, _ = make()
    assert set(conn.snapshot(ACCT)) == {"filters", "forwarding", "imap_pop"}


def test_filters_deletes_only_what_is_outside_baseline():
    conn, svc = make([{"id": "f1", **F1}, {"id": "f2", "criteria": {"from": "evil"}, "action": {}}])
    conn.run(step(conn, "filters"), {"filters": [CANON_F1]})
    svc.users().settings().filters().delete.assert_called_once_with(userId="me", id="f2")


def test_filter_identity_survives_a_changed_id():
    conn, svc = make([{"id": "new", **F1}])
    conn.run(step(conn, "filters"), {"filters": [CANON_F1]})
    assert not svc.users().settings().filters().delete.called


def test_guided_steps_never_call_the_api():
    conn, svc = make()
    with pytest.raises(NotImplementedError):
        conn.run(step(conn, "password"), {})
    assert not svc.users().settings().filters().delete.called
    assert not svc.users().settings().updateImap.called


def test_readbacks():
    conn, _ = make(fwd={"enabled": True, "emailAddress": "x@y"}, imap=True)
    assert conn.check(step(conn, "forwarding_off"), {}) is False
    assert conn.check(step(conn, "imap_pop"), {}) is False
    assert conn.check(step(conn, "sign_out"), {}) is None


def test_filters_check_and_imap_run():
    conn, svc = make([{"id": "f2", "criteria": {"x": 1}, "action": {}}])
    assert conn.check(step(conn, "filters"), {"filters": [CANON_F1]}) is False
    assert conn.check(step(conn, "filters"), {"filters": [json.dumps({"criteria": {"x": 1}, "action": {}}, sort_keys=True)]}) is True
    conn.run(step(conn, "imap_pop"), {})
    st = svc.users().settings()
    st.updateImap.assert_called_with(userId="me", body={"enabled": False})
    st.updatePop.assert_called_with(userId="me", body={"accessWindow": "disabled"})


def test_unknown_account_names_it():
    conn, _ = make()
    with pytest.raises(KeyError, match="other@example.com"):
        conn.snapshot(Account("other@example.com", "google_personal"))


def test_one_service_per_thread_and_account():
    import threading
    built = []
    conn = Personal({ACCT.id: TOKEN}, build=lambda *a, **k: built.append(1) or MagicMock())
    conn._svc(ACCT.id); conn._svc(ACCT.id)
    t = threading.Thread(target=lambda: conn._svc(ACCT.id)); t.start(); t.join()
    assert len(built) == 2


def test_catalog_titles_and_scope():
    conn, _ = make()
    assert step(conn, "revoke_apps").title == "Remove every connected app except panic-button."
    assert step(conn, "password").title.startswith("Change your password now. This disconnects panic-button;")
    assert google_personal.SCOPES == ["https://www.googleapis.com/auth/gmail.settings.basic"]


def test_missing_filters_baseline_deletes_nothing_and_raises():
    conn, svc = make([{"id": "f1", **F1}])
    for call in (conn.run, conn.check):
        with pytest.raises(KeyError, match="no baseline recorded for filters"):
            call(step(conn, "filters"), {})
    assert not svc.users().settings().filters().delete.called


def test_explicit_empty_baseline_deletes_listed_filters():
    conn, svc = make([{"id": "f1", **F1}])
    conn.run(step(conn, "filters"), {"filters": []})
    svc.users().settings().filters().delete.assert_called_once_with(userId="me", id="f1")


def test_reordered_label_lists_are_the_same_filter():
    f = {"criteria": {"from": "a@x"}, "action": {"addLabelIds": ["A", "B"], "removeLabelIds": ["X", "Y"]}}
    flipped = {"criteria": f["criteria"], "action": {"addLabelIds": ["B", "A"], "removeLabelIds": ["Y", "X"]}}
    conn, svc = make([{"id": "f1", **flipped}])
    conn.run(step(conn, "filters"), {"filters": [json.dumps(f, sort_keys=True).replace('["A", "B"]', '["A", "B"]')]})
    assert not svc.users().settings().filters().delete.called


def test_incomplete_imap_pop_response_fails_closed():
    conn, svc = make()
    svc.users().settings().getImap().execute.return_value = {}
    with pytest.raises(KeyError):
        conn.check(step(conn, "imap_pop"), {})
