"""The login item: a LaunchAgent that opens the installed app at login, where the guard starts once unlocked."""
import plistlib
from pathlib import Path

LABEL = "com.panicbutton.app"
PLIST = plistlib.dumps({"Label": LABEL, "ProgramArguments": ["/usr/bin/open", "-a", "panic button"], "RunAtLoad": True})


def _path(home=None) -> Path:
    return Path(home or Path.home()) / "Library/LaunchAgents" / f"{LABEL}.plist"


def installed(home=None) -> bool:
    return _path(home).exists()


def install(home=None) -> None:
    p = _path(home)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(PLIST)


def remove(home=None) -> None:
    _path(home).unlink(missing_ok=True)
