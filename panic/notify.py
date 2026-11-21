"""Desktop notification for the guard. Never raises: a missed banner must not stop the guard."""
import subprocess
import sys


def notify(title: str, text: str, run=subprocess.run, platform=sys.platform) -> None:
    print("\a", end="", file=sys.stderr)
    print(f"{title}: {text}", file=sys.stderr)
    if platform != "darwin":
        return
    try:  # title and text are arguments, never script source
        run(["osascript", "-e", "on run argv", "-e", "display notification (item 2 of argv) with title (item 1 of argv)",
             "-e", "end run", title, text], check=False, capture_output=True, timeout=10)
    except Exception:
        pass
