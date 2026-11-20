"""Hash-chained log: each line commits to the bytes of the line before it."""
import hashlib
import json
import time
from pathlib import Path


def _digest(line: bytes) -> str:
    return hashlib.sha256(line).hexdigest()


def append(path: Path, entry: dict) -> None:
    data = path.read_bytes() if path.exists() else b""
    # A torn tail must not merge with the new line; the chain then breaks visibly.
    prefix = b"\n" if data and not data.endswith(b"\n") else b""
    lines = data.splitlines()
    prev = _digest(lines[-1]) if lines else ""
    record = {**entry, "at": time.time(), "prev": prev}
    with path.open("ab") as f:
        f.write(prefix + json.dumps(record).encode() + b"\n")


def verify(path: Path) -> bool:
    if not path.exists():
        return True
    prev = ""
    for line in path.read_bytes().splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            return False
        if not isinstance(record, dict) or record.get("prev") != prev:
            return False
        prev = _digest(line)
    return True


def head(path: Path) -> str:
    # The last line's digest pins the whole chain; a truncated tail changes it.
    lines = path.read_bytes().splitlines() if path.exists() else []
    return _digest(lines[-1]) if lines else ""
