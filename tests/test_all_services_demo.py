import json
import socket
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_all_services_demo_runs_offline_fast_and_records_six_services(tmp_path, capsys, monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("the demo must not do this")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(time, "sleep", refuse)
    monkeypatch.setattr("panic.notify.notify", refuse)
    monkeypatch.setattr("subprocess.run", refuse)
    monkeypatch.syspath_prepend(str(ROOT))
    from demo import all_services_demo

    out = tmp_path / "run.json"
    started = time.monotonic()
    rc = all_services_demo.main(["--json", str(out)])
    took = time.monotonic() - started
    text = capsys.readouterr().out
    assert rc == 0, text
    assert text.startswith("SIMULATED PROVIDERS:") and "\nChecked: 6 services ran as described" in text
    assert took < 8
    services = json.loads(out.read_text())["services"]
    assert [s["key"] for s in services] == ["github", "outlook", "m365", "workspace", "slack", "guided"]
    assert all(s["actions"] and s["notification"] for s in services)
