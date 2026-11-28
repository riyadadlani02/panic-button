"""The sign-in apps shipped with the tool, and GitHub's device flow for signing in with one."""
import json
import os
import time
import urllib.request
from importlib.resources import files
from pathlib import Path
from urllib.parse import urlencode

DEVICE_CODE_URL = "https://github.com/login/device/code"
TOKEN_URL = "https://github.com/login/oauth/access_token"
GRANT = "urn:ietf:params:oauth:grant-type:device_code"
# The classic token's scopes, so both routes can do the same.
GITHUB_SCOPES = "repo,admin:public_key,admin:gpg_key,admin:ssh_signing_key,user,admin:repo_hook"
GITHUB_ORG_SCOPES = "admin:org,admin:org_hook"


def builtin(name: str):
    """The shipped client for google, microsoft or github; None while unset. PANIC_OAUTH_CLIENTS names another file."""
    path = os.environ.get("PANIC_OAUTH_CLIENTS")
    raw = Path(path).expanduser().read_text() if path else (files("panic") / "oauth_clients.json").read_text()
    return json.loads(raw).get(name)


def _post(url: str, fields: dict) -> dict:
    req = urllib.request.Request(url, data=urlencode(fields).encode(), headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def _show(user_code: str, uri: str) -> None:
    print(f"On GitHub, enter the code {user_code} at {uri} and click Authorize.")


def github_device_token(client_id: str, scopes: str, post=_post, sleep=time.sleep, now=time.monotonic,
                        open_url=None, show=_show) -> str:
    """A token once the owner approves on GitHub; RuntimeError when declined or expired. The code is only shown."""
    import webbrowser
    code = post(DEVICE_CODE_URL, {"client_id": client_id, "scope": scopes})
    show(code["user_code"], code["verification_uri"])
    (open_url or webbrowser.open)(code["verification_uri"])
    interval, deadline = code.get("interval", 5), now() + code["expires_in"]
    while True:
        sleep(interval)  # a cancelled job's sleep raises here, so polling stops
        if now() >= deadline:
            raise RuntimeError("the GitHub code expired before it was approved; run arm again")
        r = post(TOKEN_URL, {"client_id": client_id, "device_code": code["device_code"], "grant_type": GRANT})
        if r.get("access_token"):
            return r["access_token"]
        err = r.get("error")
        if err == "authorization_pending":
            continue
        if err == "slow_down":
            interval += 5
            continue
        if err == "access_denied":
            raise RuntimeError("you declined the request on GitHub; nothing was stored")
        if err == "expired_token":
            raise RuntimeError("the GitHub code expired before it was approved; run arm again")
        raise RuntimeError(f"GitHub sign-in failed: {err or 'no token returned'}")
