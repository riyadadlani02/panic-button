import json

import pytest


@pytest.fixture(autouse=True)
def no_builtin_sign_in_apps(tmp_path_factory, monkeypatch):
    """Tests run as if no sign-in apps were shipped; a test that wants them sets PANIC_OAUTH_CLIENTS itself."""
    p = tmp_path_factory.mktemp("oauth") / "clients.json"
    p.write_text(json.dumps({"google": None, "microsoft": None, "github": None}))
    monkeypatch.setenv("PANIC_OAUTH_CLIENTS", str(p))
