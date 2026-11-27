import json
import threading
import time

import pytest
from test_app_bridge import SECRET, box, done, wait_for  # noqa: F401  (box is a fixture)

from panic.app import keychain
from panic.app.api import CONTRACT, Api
from panic.app.bridge import Job, Runner
from panic.app.guard_thread import GuardThread



class Keyring:
    def __init__(self):
        self.d = {}

    def get_password(self, s, a):
        return self.d.get((s, a))

    def set_password(self, s, a, p):
        self.d[(s, a)] = p

    def delete_password(self, s, a):
        del self.d[(s, a)]


class Guard:
    def __init__(self, vault, keyfile, passphrase, on_question, on_notice, press_lock, now, **kw):
        self.on_question, self.now, self.press_lock = on_question, now, press_lock
        self.running = self.stopping = False
        self.code, self.output, self.open, self.answers = None, [], [], []

    def start(self):
        self.running = True

    def stop(self, timeout=3):
        self.running = False
        return True

    def questions(self):
        return list(self.open)

    def answer(self, handle, value):
        self.answers.append((handle, value))
        return True


class Window:
    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        return lambda *a: self.calls.append(name)


class Ask:
    def __init__(self, reply):
        self.reply, self.opened = reply, []

    def open_dialog(self, title, text, seconds):
        self.opened.append(title)
        return len(self.opened)

    def answer(self, proc):
        return self.reply


@pytest.fixture
def app(box, tmp_path):
    def make(runner=None, ask=None, guard=None, **kw):
        guards = []

        def factory(*a, **k):
            guards.append((guard or Guard)(*a, **k))
            return guards[-1]
        api = Api(runner or Runner(box[0], box[1], connectors={"fake": box[2]}), keyring=kr, guard=factory,
                  prefs=tmp_path / "prefs.json", home=tmp_path / "home", ask=ask or Ask(None),
                  notifier=lambda t, x: None, window=Window(), **kw)
        api.guards = guards  # test-side handle only
        return api
    kr = Keyring()
    make.keyring = kr
    return make


def test_only_the_contract_is_public(app):
    api = app()
    assert {n for n in dir(api) if not n.startswith("_")} - {"guards"} == set(CONTRACT)


def test_state_before_unlock_has_the_page_shape_and_no_accounts(app):
    s = app().state()
    assert s == {"unlocked": False, "vault_exists": True, "remember": True, "login_item": False,
                 "guard": {"running": False, "stopping": False, "last_check": None, "questions": 0}, "accounts": []}


def test_a_wrong_passphrase_stays_locked(app):
    api = app()
    r = api.unlock("nope", True)
    assert r["ok"] is False and "nope" not in r["error"] and not api.state()["unlocked"]


def test_unlock_reads_accounts_remembers_and_starts_the_guard(app, box):
    from panic import vault
    key = box[1].read_bytes()
    d = vault.load(box[0], SECRET, key)
    d["accounts"] += [{"id": "admin", "provider": "fake", "protected": True},
                      {"id": "amazon:me", "provider": "guided", "protected": False}]
    vault.save(box[0], d, SECRET, key)
    api = app()
    assert api.unlock(SECRET, True) == {"ok": True}
    s = api.state()
    assert s["unlocked"] and s["guard"]["running"]
    assert {a["id"]: a["kind"] for a in s["accounts"]} == {"mail": "guarded", "bank": "guarded",
                                                           "admin": "protected", "amazon:me": "checklist"}
    assert keychain.get(box[0], app.keyring) == SECRET
    assert SECRET not in json.dumps(s)


def test_unlock_without_remember_forgets_this_mac(app, box):
    keychain.set(box[0], SECRET, app.keyring)
    app().unlock(SECRET, False)
    assert keychain.get(box[0], app.keyring) is None


def test_launch_unlocks_from_the_keychain_unless_the_guard_was_switched_off(app, box):
    keychain.set(box[0], SECRET, app.keyring)
    api = app()
    api._launch()
    assert api.state()["unlocked"] and api.state()["guard"]["running"]
    api.guard_stop()
    again = app()
    again._launch()
    assert again.state()["unlocked"] and not again.state()["guard"]["running"]


def test_launch_with_a_stale_keychain_entry_stays_locked(app, box):
    keychain.set(box[0], "old", app.keyring)
    api = app()
    api._launch()
    assert not api.state()["unlocked"] and api.guards == []


class Rec(Runner):
    def start(self, argv):
        self.argvs = getattr(self, "argvs", []) + [argv]
        self.job = Job([])
        self.job.done = True
        return self.job


def test_start_job_maps_kinds_to_commands_and_refuses_unknown_ones(app, box):
    r = Rec(box[0], box[1])
    api = app(runner=r)
    assert api.start_job("press_all", None)["ok"] is False  # locked
    api.unlock(SECRET, False)
    for kind, extra in [("press_all", None), ("press_user", "mail"), ("checkup", None), ("checkup_again", None),
                        ("release", "bank"), ("report", None), ("setup", None)]:
        assert api.start_job(kind, extra) == {"ok": True}
    assert r.argvs == [["press", "--all"], ["press", "--user=mail"], ["checkup"], ["checkup", "--again"],
                       ["release", "--user=bank"], ["report"], ["setup"]]
    assert api.start_job("press_user", None)["ok"] is False
    assert api.start_job("rm", None) == {"ok": False, "error": "unknown job"}


def test_a_second_job_is_busy(app):
    api = app()
    api.unlock(SECRET, False)
    assert api.start_job("checkup", None) == {"ok": True}
    assert api.start_job("report", None) == {"ok": False, "error": "busy"}
    api.job_cancel()


def test_setup_creates_the_vault_then_unlocks_remembers_and_guards(app, tmp_path):
    v, k = tmp_path / "new.vault", tmp_path / "new.key"
    api = app(runner=Runner(v, k, connectors={}))
    assert api.state()["vault_exists"] is False
    assert api.start_job("setup", None) == {"ok": True}
    replies = {"Number": "7", "Which service": "amazon", "login there": "me@x.test", "Choose": SECRET,
               "Repeat": SECRET, "another": "n"}
    seen = []

    def step():
        ev = api.job_events(len(seen))
        seen.extend(ev)
        for e in ev:
            if e["type"] == "prompt":
                assert api.job_answer(e["id"], next((a for t, a in replies.items() if t in e["text"]), "y"))
        return any(e["type"] == "done" for e in seen)
    wait_for(step)
    s = api.state()
    assert s["vault_exists"] and s["unlocked"] and s["guard"]["running"]
    assert [a["id"] for a in s["accounts"]] == ["amazon:me@x.test"]
    assert keychain.get(v, app.keyring) == SECRET
    assert SECRET not in json.dumps(seen) + json.dumps(s)


def test_questions_pass_through_and_only_accept_or_lock_is_taken(app):
    api = app()
    api.unlock(SECRET, False)
    g = api.guards[0]
    g.open = [{"handle": 1, "account": "mail", "text": "New filter", "deadline": 9e9}]
    assert api.questions() == g.open
    assert api.answer_question(1, "lock") is True and api.answer_question(1, "none") is False
    assert g.answers == [(1, "lock")]


def test_last_check_comes_from_the_guard_pass(app):
    api = app()
    api.unlock(SECRET, False)
    t = api.guards[0].now()
    assert api.state()["guard"]["last_check"] == t


def test_the_real_guard_reports_its_last_check(app, box):
    api = app(guard=GuardThread, connectors={"fake": box[2]})
    api.unlock(SECRET, False)
    try:
        wait_for(lambda: api.state()["guard"]["last_check"])
    finally:
        api.guards[0].stop()


def test_reports_lists_this_vaults_reports_and_reads_only_those(app, box):
    api = app()
    assert api.reports() == []  # locked
    api.unlock(SECRET, False)
    (box[0].parent / f"{box[0].name}.report-20261120T081500Z.md").write_text("# Press\nmail locked\n")
    (box[0].parent / f"{box[0].name}.report-20261120T081500Z.json").write_text("{}")
    (box[0].parent / "other.md").write_text("secret")
    name = f"{box[0].name}.report-20261120T081500Z.md"
    assert api.reports() == [{"name": name, "when": "2026-11-20T08:15:00Z"}]
    assert api.report(name) == "# Press\nmail locked\n"
    assert api.report("../other.md") == "" and api.report("other.md") == ""


def test_login_item_switch(app, tmp_path):
    api = app()
    api.set_login_item(True)
    assert api.state()["login_item"] and (tmp_path / "home/Library/LaunchAgents/com.panicbutton.app.plist").exists()
    api.set_login_item(False)
    assert not api.state()["login_item"]


def test_quit_keeping_the_guard_hides_and_asks_through_the_mac_dialog(app):
    ask = Ask("lock")
    api = app(ask=ask)
    api.unlock(SECRET, False)
    g = api.guards[0]
    g.open = [{"handle": 1, "account": "mail", "text": "New filter", "deadline": 9e9}]
    api.quit(True)
    assert api._window.calls == ["hide"] and g.running
    wait_for(lambda: g.answers == [(1, "lock")])
    g.on_question({"handle": 2, "account": "bank", "text": "New forward", "deadline": 9e9})  # opened while hidden
    wait_for(lambda: (2, "lock") in g.answers)
    assert ask.opened == ["panic: mail", "panic: bank"]


def test_questions_stay_in_the_window_while_it_shows(app):
    ask = Ask("lock")
    api = app(ask=ask)
    api.unlock(SECRET, False)
    api.guards[0].on_question({"handle": 1, "account": "mail", "text": "x", "deadline": 9e9})
    assert ask.opened == []


def test_quit_stops_the_guard_waits_for_a_press_then_closes(app):
    api = app()
    api.unlock(SECRET, False)
    g = api.guards[0]
    g.press_lock.acquire()  # a press in flight
    t = threading.Thread(target=api.quit, args=(False,), daemon=True)
    t.start()
    wait_for(lambda: not g.running)
    assert "destroy" not in api._window.calls
    g.press_lock.release()
    t.join(3)
    assert api._window.calls == ["destroy"]
    assert api._closing() is True  # the window may now close


def test_closing_the_window_asks_first(app):
    api = app()
    assert api._closing() is False
    wait_for(lambda: api._window.calls == ["evaluate_js"])


# -- fix round 1 --

def test_the_page_reaches_only_the_contract_through_the_real_bridge(app):
    webview = pytest.importorskip("webview")
    from webview.util import js_bridge_call

    from panic.app import __main__ as main
    api = app()
    api.unlock(SECRET, False)
    w = main._open(api)
    calls = []
    w.evaluate_js = lambda js: calls.append(js)
    try:
        for name in ["__dict__", "state.__globals__.keychain.get", "_runner", "_passphrase", "_runner._passphrase",
                     "unlock.__globals__", "state.__self__._vault.unlink", "_prefs.write_text"]:
            js_bridge_call(w, name, [], "1")
        time.sleep(0.3)
        assert calls == []
        js_bridge_call(w, "questions", [], "2")  # the contract still works
        wait_for(lambda: calls)
        assert sorted(w._functions) == sorted(CONTRACT)
    finally:
        webview.windows.remove(w)


def test_a_second_close_while_quit_waits_for_a_press_is_refused(app):
    api = app()
    api.unlock(SECRET, False)
    lock = api.guards[0].press_lock
    lock.acquire()
    t = threading.Thread(target=api.quit, args=(False,), daemon=True)
    t.start()
    time.sleep(0.2)
    try:
        assert api._closing() is False  # the press is still running
    finally:
        lock.release()
    t.join(3)
    assert api._closing() is True


def test_methods_that_fail_say_so_instead_of_raising(app, box, tmp_path):
    class Broken(Keyring):
        def delete_password(self, s, a):
            raise RuntimeError("keychain locked")
    api = app()
    api._keyring = Broken()
    keychain.set(box[0], "x", api._keyring)
    assert api.forget_mac() == {"ok": False, "error": "RuntimeError: keychain locked"}
    (tmp_path / "home").write_text("not a folder")
    assert api.set_login_item(True)["ok"] is False
    api.unlock(SECRET, False)
    api._prefs = tmp_path / "home" / "prefs.json"  # its folder is a file
    assert api.guard_stop()["ok"] is False and not api.guards[0].running  # stopped all the same
    name = f"{box[0].name}.report-20261120T081500Z.md"
    (box[0].parent / name).write_bytes(b"\xff\xfe bad")
    assert api.report(name)["ok"] is False


def test_one_mac_dialog_per_question_closed_once_answered_in_the_window(app):
    class Open(Ask):
        def __init__(self):
            super().__init__(None)
            self.closed = []

        def close(self, proc):
            self.closed.append(proc)
    ask = Open()
    api = app(ask=ask)
    api.unlock(SECRET, False)
    g = api.guards[0]
    q = {"handle": 1, "account": "mail", "text": "New filter", "deadline": 9e9}
    g.open = [q]
    api.quit(True)
    g.on_question(q)  # reported again while its dialog is open
    api.quit(True)
    time.sleep(0.3)
    assert ask.opened == ["panic: mail"]
    g.open = []  # answered in the window
    wait_for(lambda: ask.closed == [1])
    assert g.answers == []


def test_setup_unlock_runs_once_when_two_polls_race(app, box):
    class Slow:
        @property
        def done(self):
            time.sleep(0.1)
            return True
    r = Runner(box[0], box[1])
    unlocks = []
    real = r.unlock
    r.unlock = lambda pw: (unlocks.append(pw), real(pw))
    api = app(runner=r)
    r.job, api._new_passphrase = Slow(), SECRET
    ts = [threading.Thread(target=api._after_setup) for _ in range(2)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert len(unlocks) == 1


def test_the_api_keeps_no_copy_of_the_passphrase(app):
    api = app()
    api.unlock(SECRET, False)
    assert SECRET not in [v for v in vars(api).values() if isinstance(v, str)]
