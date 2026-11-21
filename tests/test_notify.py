from panic.notify import notify

INJECT = '"; do shell script "x'


def test_text_is_an_argument_never_script_source():
    calls = []
    notify("t", INJECT, run=lambda argv, **k: calls.append(argv), platform="darwin")
    argv = calls[0]
    assert argv[0] == "osascript" and argv[-1] == INJECT and argv[-2] == "t"
    assert not any(INJECT in x for x in argv[:-1])


def test_other_platforms_do_not_run_anything():
    calls = []
    notify("t", "x", run=lambda *a, **k: calls.append(a), platform="linux")
    assert calls == []


def test_a_failing_run_never_raises():
    def boom(*a, **k):
        raise OSError("no osascript")
    notify("t", "x", run=boom, platform="darwin")
