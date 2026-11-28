import json

import pytest

from panic import oauth
from panic.session import CliError

CODE = {"device_code": "dc", "user_code": "ABCD-1234", "verification_uri": "https://github.com/login/device",
        "expires_in": 900, "interval": 5}


def test_the_shipped_file_has_every_id_unset(monkeypatch):
    monkeypatch.delenv("PANIC_OAUTH_CLIENTS")
    assert [oauth.builtin(k) for k in ("google", "microsoft", "github")] == [None, None, None]


def test_the_env_file_overrides_the_shipped_one(tmp_path, monkeypatch):
    p = tmp_path / "clients.json"
    p.write_text(json.dumps({"github": "gh-id", "google": {"installed": {"client_id": "g"}}}))
    monkeypatch.setenv("PANIC_OAUTH_CLIENTS", str(p))
    assert oauth.builtin("github") == "gh-id" and oauth.builtin("google") == {"installed": {"client_id": "g"}}
    assert oauth.builtin("microsoft") is None


@pytest.mark.parametrize("text", [None, "{not json", "[1, 2]"])
def test_a_missing_malformed_or_non_object_env_file_is_one_clear_error(tmp_path, monkeypatch, text):
    p = tmp_path / "clients.json"
    if text is not None:
        p.write_text(text)
    monkeypatch.setenv("PANIC_OAUTH_CLIENTS", str(p))
    with pytest.raises(CliError, match=f"PANIC_OAUTH_CLIENTS {p}"):
        oauth.builtin("github")


def flow(replies, sleep=None):
    """Runs the device flow against canned replies; the clock moves only when it sleeps."""
    clock, posts, slept, shown, opened = [0.0], [], [], [], []
    it = iter(replies)

    def post(url, fields):
        posts.append((url, fields))
        return next(it)

    def _sleep(s):
        slept.append(s)
        clock[0] += s

    try:
        token = oauth.github_device_token("cid", "repo,user", post=post, sleep=sleep or _sleep, now=lambda: clock[0],
                                          open_url=opened.append, show=lambda c, u: shown.append((c, u)))
    except BaseException as e:
        token = e
    return token, posts, slept, shown, opened


def test_pending_then_slow_down_then_success():
    token, posts, slept, shown, opened = flow([CODE, {"error": "authorization_pending"}, {"error": "slow_down"},
                                               {"access_token": "gho_x"}])
    assert token == "gho_x" and slept == [5, 5, 10]
    assert shown == [("ABCD-1234", "https://github.com/login/device")] and opened == ["https://github.com/login/device"]
    assert posts[0] == (oauth.DEVICE_CODE_URL, {"client_id": "cid", "scope": "repo,user"})
    assert posts[1] == (oauth.TOKEN_URL, {"client_id": "cid", "device_code": "dc",
                                          "grant_type": "urn:ietf:params:oauth:grant-type:device_code"})


def test_denied_stops_with_a_clear_error():
    err, posts, *_ = flow([CODE, {"error": "access_denied"}, {"access_token": "never"}])
    assert isinstance(err, RuntimeError) and "declined" in str(err) and len(posts) == 2


def test_expired_token_stops_with_a_clear_error():
    err, posts, *_ = flow([CODE, {"error": "expired_token"}, {"access_token": "never"}])
    assert isinstance(err, RuntimeError) and "expired" in str(err) and len(posts) == 2


def test_it_stops_once_the_code_has_expired_without_asking_again():
    err, posts, *_ = flow([{**CODE, "expires_in": 12}] + [{"error": "authorization_pending"}] * 10)
    assert isinstance(err, RuntimeError) and "expired" in str(err) and len(posts) == 3  # polled at 5 s and 10 s


def test_a_cancelled_job_stops_polling():
    def cancelled(s):
        raise KeyboardInterrupt

    err, posts, *_ = flow([CODE, {"access_token": "never"}], sleep=cancelled)
    assert isinstance(err, KeyboardInterrupt) and len(posts) == 1
