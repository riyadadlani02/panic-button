from panic.ask import answer, open_dialog


class FakeProc:
    def __init__(self, out="", code=0, running=False):
        self.out, self.code, self.running = out, code, running

    def poll(self):
        return None if self.running else self.code

    def communicate(self):
        return self.out, ""


def test_open_dialog_passes_title_and_text_as_trailing_argv():
    seen = {}

    def popen(cmd, **kw):
        seen["cmd"], seen["kw"] = cmd, kw
        return FakeProc()

    assert open_dialog("T; evil", "body \"x\"", 30, popen=popen, platform="darwin") is not None
    assert seen["cmd"][-3:] == ["T; evil", "body \"x\"", "30"]
    assert "T; evil" not in " ".join(seen["cmd"][:-3])


def test_open_dialog_none_off_macos_or_on_error():
    assert open_dialog("t", "x", 5, popen=lambda *a, **k: FakeProc(), platform="linux") is None

    def boom(*a, **k):
        raise OSError

    assert open_dialog("t", "x", 5, popen=boom, platform="darwin") is None


def test_answer_parses_buttons():
    assert answer(FakeProc("button returned:It was me, gave up:false\n")) == "accept"
    assert answer(FakeProc("button returned:Lock it down, gave up:false\n")) == "lock"


def test_answer_none_when_still_open():
    assert answer(FakeProc(running=True)) is None


def test_answer_none_string_when_gave_up_failed_or_garbled():
    assert answer(FakeProc("button returned:, gave up:true")) == "none"
    assert answer(FakeProc("button returned:It was me, gave up:false", code=1)) == "none"
    assert answer(FakeProc("garbage")) == "none"
    assert answer(object()) == "none"
