"""Small JSON-over-HTTPS client shared by the API connectors."""
import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any
from urllib.parse import urlencode, urljoin, urlsplit

MAX_HOPS = 3
RETRIES = 3


class ApiError(Exception):
    """`body` is for diagnostics and may hold provider data; the message never does."""

    def __init__(self, status: int, body: str, message: str | None = None):
        super().__init__(message or f"HTTP {status}")
        self.status, self.body = status, body[:200]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # urllib would resend the Authorization header; Api decides itself
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def _decode(raw: bytes) -> str:
    return raw.decode("utf-8", "replace")


class Api:
    """One provider's API. Credentials only ever go to the host of `base`; safe to share between threads."""

    def __init__(self, base: str, headers: Callable[[], dict[str, str]], open=_opener.open, sleep=time.sleep,
                 timeout: float = 30):
        self._base, self._headers, self._open, self._sleep, self._timeout = base.rstrip("/"), headers, open, sleep, timeout

    def _url(self, path: str, params: dict | None = None) -> str:
        parts = urlsplit(path)
        if parts.scheme or parts.netloc:
            base = urlsplit(self._base)
            if (parts.scheme != "https" or parts.username is not None
                    or (parts.hostname, parts.port) != (base.hostname, base.port)):
                raise ValueError("refusing to send credentials to another host")
            url = path
        else:
            url = f"{self._base}/{path.lstrip('/')}"
        return url + (("&" if "?" in url else "?") + urlencode(params) if params else "")

    def _fetch(self, method: str, url: str, body: Any = None) -> tuple[Any, bytes]:
        data = None if body is None else json.dumps(body).encode()
        tries = hops = 0
        while True:
            headers = {**self._headers(), **({"Content-Type": "application/json"} if data else {})}
            req = urllib.request.Request(url, data=data, headers=headers, method=method)
            try:
                with self._open(req, timeout=self._timeout) as r:
                    status, hdrs, raw = r.status, r.headers, r.read()
            except urllib.error.HTTPError as e:
                status, hdrs, raw = e.code, e.headers, e.read()
            if 200 <= status < 300:
                return hdrs, raw
            where = f"{method} {urlsplit(url)._replace(query='').geturl()}"  # the query may carry anything
            if status in (301, 302, 303, 307, 308) and hdrs.get("Location"):
                hops += 1
                try:
                    url = self._url(urljoin(url, hdrs["Location"]))
                except ValueError:
                    raise ApiError(status, "", f"{where}: redirect to another host refused")
                if hops > MAX_HOPS:
                    raise ApiError(status, "", f"{where}: too many redirects")
                continue
            if (status == 429 or status >= 500) and tries < RETRIES:
                try:  # 0..60 s: a hostile or odd header must neither stall the guard nor raise
                    wait = max(0.0, min(float(hdrs.get("Retry-After")), 60.0))
                except (TypeError, ValueError):
                    wait = 2 ** tries
                tries += 1
                self._sleep(wait)
                continue
            raise ApiError(status, _decode(raw), f"{where}: HTTP {status}")

    @staticmethod
    def _json(raw: bytes) -> Any:
        if not raw.strip():
            return None
        try:
            return json.loads(raw)
        except ValueError:
            raise ApiError(200, _decode(raw), "response was not JSON")

    def get(self, path: str, params: dict | None = None) -> Any:
        return self._json(self._fetch("GET", self._url(path, params))[1])

    def send(self, method: str, path: str, body: dict | None = None) -> Any:
        return self._json(self._fetch(method, self._url(path), body)[1])

    def delete(self, path: str, gone_ok: bool = True) -> None:
        try:
            self._fetch("DELETE", self._url(path))
        except ApiError as e:
            if not (gone_ok and e.status == 404):
                raise

    @staticmethod
    def _next(hdrs) -> str | None:
        for part in (hdrs.get("Link") or "").split(","):
            url, _, rest = part.strip().partition(">;")
            if 'rel="next"' in rest and url.startswith("<"):
                return url[1:]
        return None

    def pages(self, path: str, params: dict | None = None) -> list:
        url, out, seen = self._url(path, params), [], set()
        while url and url not in seen:  # a server that loops its own Link must not loop us
            seen.add(url)
            hdrs, raw = self._fetch("GET", url)
            page = self._json(raw)
            if not isinstance(page, list):
                raise ApiError(200, _decode(raw), "expected a list")
            out += page
            nxt = self._next(hdrs)
            url = self._url(nxt) if nxt else None
        return out
