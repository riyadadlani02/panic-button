"""Owner dialog for the guard. Never raises: a dialog problem must not stop the guard."""
import subprocess
import sys

_SCRIPT = ["-e", "on run argv", "-e",
           'display dialog (item 2 of argv) with title (item 1 of argv) buttons {"Lock it down", "It was me"} '
           'giving up after ((item 3 of argv) as integer)', "-e", "end run"]


def open_dialog(title: str, text: str, seconds: int, popen=subprocess.Popen, platform=sys.platform):
    if platform != "darwin":
        return None
    try:  # title and text are arguments, never script source
        return popen(["osascript", *_SCRIPT, title, text, str(max(1, int(seconds)))],
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except Exception:
        return None


def answer(proc):
    """None while open; otherwise "accept", "lock" or "none" (gave up, closed or failed)."""
    try:
        code = proc.poll()
        if code is None:
            return None
        out, _ = proc.communicate()
        if code != 0:
            return "none"
        if "gave up:true" in out:
            return "none"
        if "button returned:It was me" in out:
            return "accept"
        if "button returned:Lock it down" in out:
            return "lock"
    except Exception:
        pass
    return "none"


def close(proc) -> None:
    """Takes an open dialog away, as when the question was answered elsewhere."""
    try:
        proc.kill()
    except Exception:
        pass
