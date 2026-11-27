import json
import sys
import threading
import time

import pytest
from fake import FakeConnector
from test_cli import HIDE, _steps

from panic import vault
from panic.app import keychain
from panic.app.bridge import Busy, Runner
from panic.app.guard_thread import GuardThread
from panic.model import Finding, Severity
from panic.vault import VaultError

SECRET = "Correct-Horse-9271"


@pytest.fixture
def box(tmp_path):
    v, k = tmp_path / "panic.vault", tmp_path / "key"
    key = vault.new_keyfile()
    k.write_bytes(key)
    vault.save(v, {"accounts": [{"id": "mail", "provider": "fake", "protected": False},
                                {"id": "bank", "provider": "fake", "protected": False}],
                   "edges": [["mail", "bank"]], "baselines": {"mail": {}, "bank": {}}, "credentials": {},
                   "released": []}, SECRET, key)
    return v, k, FakeConnector(steps=_steps())


def wait_for(cond, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if r := cond():
            return r
        time.sleep(0.02)
    raise AssertionError("timed out")


def prompt(job, after=-1):
    return wait_for(lambda: next((e for e in job.events() if e["type"] == "prompt" and e["id"] > after), None))


def done(job):
    return wait_for(lambda: next((e for e in job.events() if e["type"] == "done"), None))


def done_now(job):
    return next((e for e in job.events() if e["type"] == "done"), None)


def text(job):
    return "".join(e["text"] for e in job.events() if e["type"] == "output")


def load(box):
    return vault.load(box[0], SECRET, box[1].read_bytes())


def runner(box, **kw):
    r = Runner(box[0], box[1], connectors={"fake": box[2]}, **kw)
    r.unlock(SECRET)
    return r


def test_arm_guided_job_asks_through_events_and_finishes(box):
    job = runner(box).start(["arm", "--guided", "amazon", "--id", "me@x.test"])
    first = prompt(job)
    assert first["secret"] is False and job.answer(first["id"], "y")
    second = prompt(job, first["id"])
    assert not job.answer(first["id"], "mail")  # a stale id never answers a later prompt
    assert job.answer(second["id"], "mail")
    assert done(job) == {"type": "done", "code": 0}
    assert "amazon:me@x.test" in [a["id"] for a in load(box)["accounts"]]
    events = json.dumps(job.events())
    assert SECRET not in events and "Passphrase" not in events


def test_cancel_ends_a_waiting_job_with_cancelled(box):
    job = runner(box).start(["arm", "--guided", "amazon", "--id", "me@x.test"])
    prompt(job)
    time.sleep(0.3)  # an unanswered prompt waits; nothing answers it by default
    assert done_now(job) is None
    job.cancel()
    assert done(job)["code"] == 1 and "Cancelled." in text(job)
    assert "amazon:me@x.test" not in [a["id"] for a in load(box)["accounts"]]


def test_a_second_job_is_refused_while_one_runs(box):
    r = runner(box)
    job = r.start(["arm", "--guided", "amazon", "--id", "me@x.test"])
    prompt(job)
    with pytest.raises(Busy):
        r.start(["map"])
    job.cancel()
    done(job)
    assert done(r.start(["map"]))["code"] == 0


def test_a_locked_runner_routes_the_passphrase_as_a_secret_prompt_never_echoed(box, capsys):
    job = Runner(box[0], box[1], connectors={"fake": box[2]}).start(["map"])
    p = prompt(job)
    assert p["secret"] is True and p["text"].startswith("Passphrase")
    print("from the test thread")  # other threads are not routed
    job.answer(p["id"], SECRET)
    assert done(job)["code"] == 0 and "can reset" in text(job)
    assert SECRET not in json.dumps(job.events()) and "from the test thread" not in text(job)
    assert "from the test thread" in capsys.readouterr().out


def test_unlock_refuses_a_wrong_passphrase(box):
    r = Runner(box[0], box[1])
    with pytest.raises(VaultError):
        r.unlock("wrong")
    assert r.passphrase is None


def test_a_manual_press_waits_for_the_shared_lock_and_cancel_stops_its_watch(box):
    lock = threading.Lock()
    with lock:
        job = runner(box, press_lock=lock).start(["press", "--all"])
        time.sleep(0.5)
        assert box[2].ran == []
    wait_for(lambda: "Watching for" in text(job))
    assert box[2].ran
    job.cancel()
    assert done(job)["code"] == 0 and "Watch stopped." in text(job)


class Backend:
    def __init__(self):
        self.d = {}

    def get_password(self, service, account):
        return self.d.get((service, account))

    def set_password(self, service, account, pw):
        self.d[(service, account)] = pw

    def delete_password(self, service, account):
        del self.d[(service, account)]


def test_keychain_saves_gets_and_forgets_by_vault_path(box):
    b = Backend()
    keychain.set(box[0], SECRET, backend=b)
    assert b.d == {("panic-button", str(box[0].absolute())): SECRET}
    assert keychain.get(box[0], backend=b) == SECRET
    keychain.delete(box[0], backend=b)
    keychain.delete(box[0], backend=b)  # forgetting twice is fine
    assert keychain.get(box[0], backend=b) is None


def test_keychain_without_keyring_reads_nothing_and_refuses_to_save(box, monkeypatch):
    monkeypatch.setitem(sys.modules, "keyring", None)
    assert keychain.get(box[0]) is None
    with pytest.raises(keychain.KeychainError, match="keyring"):
        keychain.set(box[0], SECRET)


def trigger(fake):
    fake.signals = lambda acct, snap, base: (
        [Finding(acct.id, "rule_hides_mail", Severity.TRIGGER, HIDE, ("rule-json",))] if acct.id == "mail" else [])


def test_guard_thread_asks_the_app_and_a_lock_answer_presses(box):
    trigger(box[2])
    seen = []
    g = GuardThread(box[0], box[1], SECRET, on_question=seen.append, connectors={"fake": box[2]})
    g.start()
    q = wait_for(g.questions)[0]
    assert q["account"] == "mail" and HIDE in q["text"] and q["deadline"] > time.time() and seen == [q]
    assert box[2].ran == [] and len(g.questions()) == 1
    assert g.answer(q["handle"], "lock")
    wait_for(lambda: box[2].ran)
    assert g.questions() == []
    t = time.time()
    assert g.stop() and time.time() - t < 3 and not g.running
    assert load(box)["outcomes"] and SECRET not in "".join(g.output)
    assert "Guard stopped." in "".join(g.output)


def test_a_guard_press_waits_while_the_shared_lock_is_held(box):
    trigger(box[2])
    lock = threading.Lock()
    g = GuardThread(box[0], box[1], SECRET, press_lock=lock, connectors={"fake": box[2]})
    g.start()
    q = wait_for(g.questions)[0]
    with lock:
        g.answer(q["handle"], "lock")
        time.sleep(1.5)
        assert box[2].ran == []
    wait_for(lambda: box[2].ran)
    assert g.stop()
