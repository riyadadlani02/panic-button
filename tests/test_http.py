import io
import urllib.error
from email.message import Message

import pytest

from panic.http import Api, ApiError

BASE = "https://api.test"


def msg(headers=None):
    m = Message()
    for k, v in (headers or {}).items():
        m[k] = v
    return m


class Resp:
    def __init__(self, body=b"", status=200, headers=None):
        self.status, self._body, self.headers = status, body, msg(headers)

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def err(status, body=b"", headers=None):
    return urllib.error.HTTPError(BASE + "/x", status, "x", msg(headers), io.BytesIO(body))


class Script:
    """Fake `open`: replays the given responses and records each request."""

    def __init__(self, *items):
        self.items, self.requests = list(items), []

    def __call__(self, req, timeout=None):
        self.requests.append(req)
        item = self.items.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    @property
    def urls(self):
        return [r.full_url for r in self.requests]


def api(*items):
    script, sleeps = Script(*items), []
    return Api(BASE, lambda: {"Authorization": "Bearer secret"}, open=script, sleep=sleeps.append), script, sleeps


def test_pages_follows_next_link_until_exhausted():
    a, s, _ = api(Resp(b'[1, 2]', headers={"Link": f'<{BASE}/items?page=2>; rel="next", <{BASE}/items?page=9>; rel="last"'}),
                  Resp(b'[3]'))
    assert a.pages("/items", {"per_page": 2}) == [1, 2, 3]
    assert s.urls == [BASE + "/items?per_page=2", BASE + "/items?page=2"]
    assert all(r.get_header("Authorization") == "Bearer secret" for r in s.requests)


def test_pages_can_take_the_list_from_a_wrapping_object():
    a, s, _ = api(Resp(b'{"total_count": 3, "runners": [1, 2]}', headers={"Link": f'<{BASE}/items?page=2>; rel="next"'}),
                  Resp(b'{"runners": [3]}'))
    assert a.pages("/items", key="runners") == [1, 2, 3]
    a, s, _ = api(Resp(b'{"other": []}'))
    with pytest.raises(ApiError):
        a.pages("/items", key="runners")


def test_429_sleeps_retry_after_then_succeeds():
    a, s, sleeps = api(err(429, headers={"Retry-After": "3"}), Resp(b'{"ok": true}'))
    assert a.get("/x") == {"ok": True} and sleeps == [3.0] and len(s.requests) == 2


def test_four_500s_raise_after_backoff():
    a, s, sleeps = api(*[err(500, b"boom") for _ in range(4)])
    with pytest.raises(ApiError) as e:
        a.get("/x")
    assert e.value.status == 500 and sleeps == [1, 2, 4] and len(s.requests) == 4


def test_delete_treats_404_as_gone_unless_told_otherwise():
    a, _, _ = api(err(404))
    assert a.delete("/x") is None
    a, _, _ = api(err(404))
    with pytest.raises(ApiError):
        a.delete("/x", gone_ok=False)


def test_403_raises_at_once_with_a_trimmed_body_and_no_token_in_the_message():
    a, s, sleeps = api(err(403, b"x" * 500))
    with pytest.raises(ApiError) as e:
        a.get("/x")
    assert e.value.status == 403 and len(e.value.body) == 200 and sleeps == [] and len(s.requests) == 1
    assert "secret" not in str(e.value)


@pytest.mark.parametrize("url", ["https://evil.test/x", "http://api.test/x", "//evil.test/x",
                                 "https://api.test@evil.test/x", "https://api.test:8443/x"])
def test_other_host_is_refused_before_any_request(url):
    a, s, _ = api()
    for call in (a.get, a.pages, a.delete, lambda u: a.send("POST", u, {})):
        with pytest.raises(ValueError):
            call(url)
    assert s.requests == []


def test_absolute_url_on_the_same_host_is_used_as_is():
    a, s, _ = api(Resp(b'[]'))
    assert a.pages(BASE + "/items?page=2") == [] and s.urls == [BASE + "/items?page=2"]


def test_next_link_to_another_host_is_never_followed():
    a, s, _ = api(Resp(b'[1]', headers={"Link": '<https://evil.test/p2>; rel="next"'}))
    with pytest.raises(ValueError):
        a.pages("/items")
    assert len(s.requests) == 1


def test_redirect_to_another_host_is_refused():
    a, s, _ = api(err(302, headers={"Location": "https://evil.test/steal"}))
    with pytest.raises(ApiError) as e:
        a.get("/x")
    assert e.value.status == 302 and len(s.requests) == 1


def test_redirect_on_the_same_host_is_followed():
    a, s, _ = api(err(301, headers={"Location": "/y"}), Resp(b'1'))
    assert a.get("/x") == 1 and s.urls == [BASE + "/x", BASE + "/y"]
    assert s.requests[1].get_header("Authorization") == "Bearer secret"


def test_send_posts_json_and_empty_body_is_none():
    a, s, _ = api(Resp(b'{"id": 1}', 201), Resp(b'', 204))
    assert a.send("POST", "/things", {"a": 1}) == {"id": 1}
    assert a.send("DELETE", "/things/1") is None
    r = s.requests[0]
    assert r.get_method() == "POST" and r.data == b'{"a": 1}' and r.get_header("Content-type") == "application/json"
    assert s.requests[1].data is None


@pytest.mark.parametrize("value, wait", [("3600", 60.0), ("-5", 0.0), ("soon", 1), ("nan", 0.0)])
def test_retry_after_is_clamped_and_never_raises(value, wait):
    a, s, sleeps = api(err(429, headers={"Retry-After": value}), Resp(b'{"ok": true}'))
    assert a.get("/x") == {"ok": True} and sleeps == [wait]
