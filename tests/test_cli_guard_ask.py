import test_cli
from test_cli import armed, bare, guard, open_vault, trigger  # noqa: F401

from panic.model import Finding, Severity


class Asker:
    def __init__(self, reply):
        self.reply, self.opened = reply, []

    def open_dialog(self, title, text, seconds, **kw):
        self.opened.append((title, text, seconds))
        return object()

    def answer(self, proc):
        return self.reply


def run(guard, asker, *args):
    return guard.run("--wait", "900", "--passes", "1", *args, asker=asker)


def test_negative_wait_is_an_error(guard, capsys):
    assert guard.run("--wait", "-1", "--passes", "1") == 1
    assert "--wait must be 0 or more seconds." in capsys.readouterr().err


def test_a_trigger_is_asked_not_pressed(guard):
    trigger("mail")
    asker = Asker(None)
    assert run(guard, asker) == 0
    assert len(open_vault()["guard"]["asks"]) == 1 and test_cli.fake.ran == [] and "outcomes" not in open_vault()
    title, text, seconds = asker.opened[0]
    assert title == "panic: mail" and "locked at" in text and 0 < seconds <= 900
    assert guard.notes[0][1].endswith("Lock it? Run `panic press --user mail`.")


def test_a_lock_answer_presses_without_waiting_the_interval(guard):
    trigger("mail")
    assert guard.run("--wait", "900", "--passes", "2", asker=Asker("lock")) == 0
    assert open_vault()["outcomes"] and 300 not in guard.sleeps


def test_an_accept_answer_saves_the_new_baseline(guard):
    test_cli.fake.snap = {"forward": ["new@x.test"]}
    test_cli.fake.signals = lambda acct, snap, base: (
        [Finding(acct.id, "forwarding_added", Severity.NOTICE, "Forwarding added.")] if snap != base else [])
    assert guard.run("--wait", "900", "--passes", "2", asker=Asker("accept")) == 0
    assert open_vault()["baselines"]["mail"] == {"forward": ["new@x.test"]} and test_cli.fake.ran == []


def test_an_overdue_ask_on_an_unreadable_account_waits_for_the_interval(guard):
    test_cli.fake.signals = lambda acct, snap, base: []
    trigger("mail")
    run(guard, Asker(None))
    d = open_vault()
    for v in d["guard"]["asks"].values():
        v["deadline"] = 0
    test_cli.vault.save(test_cli.vpath, d, test_cli.PW, test_cli.kpath.read_bytes())

    def boom(account):
        raise RuntimeError("down")

    test_cli.fake.snapshot = boom
    guard.sleeps.clear()
    assert guard.run("--wait", "900", "--passes", "2", asker=Asker(None)) == 0
    assert len(guard.sleeps) == 300


def test_a_failed_save_of_an_answer_does_not_end_the_guard(guard, monkeypatch):
    from panic.session import Session
    trigger("mail")

    class Breaking(Asker):
        def answer(self, proc):
            def fail(self, fn):
                raise OSError("disk full")
            monkeypatch.setattr(Session, "update", fail)
            return "lock"

    assert guard.run("--wait", "900", "--passes", "2", asker=Breaking(None)) == 0
    assert any("saving an answer failed" in x for _, x in guard.notes)
