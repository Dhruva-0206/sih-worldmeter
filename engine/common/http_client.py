"""Shared, rate-limited HTTP client for every DAST module.

Centralizing this means the `safety.max_requests_per_second` /
`request_timeout_seconds` config values apply uniformly, and — more
importantly — every probe goes through the same base_url that
config.load_scan_config() already validated as local/docker-scoped. No DAST
module constructs its own requests.Session pointed at an arbitrary host.
"""
from __future__ import annotations

import json as _json
import time
from dataclasses import dataclass, field
from typing import Any

import requests


@dataclass
class SafeResponse:
    status_code: int
    headers: dict[str, str]
    text: str
    elapsed_seconds: float
    url: str
    error: str | None = None
    # Parsed from requests' cookie jar, not from `headers['Set-Cookie']` —
    # a plain dict(resp.headers) collapses multiple Set-Cookie response
    # headers down to whichever one wins the key collision, silently
    # dropping the others (a real bug caught during development: worldmonitor
    # sends a session cookie AND a separate pro-key-clearing cookie on the
    # same response, and dict(headers) kept only the latter).
    cookies: dict[str, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.error is None

    def json(self) -> Any:
        return _json.loads(self.text)


class RateLimiter:
    def __init__(self, max_requests_per_second: float):
        self._min_interval = 1.0 / max_requests_per_second if max_requests_per_second > 0 else 0.0
        self._last_call = 0.0

    def wait(self) -> None:
        if self._min_interval <= 0:
            return
        now = time.monotonic()
        delta = now - self._last_call
        if delta < self._min_interval:
            time.sleep(self._min_interval - delta)
        self._last_call = time.monotonic()


class SafeClient:
    """Thin wrapper over `requests` scoped to one base_url, rate-limited,
    never following redirects automatically (each DAST module decides
    whether a 3xx matters to it and inspects Location itself)."""

    def __init__(self, base_url: str, max_requests_per_second: float = 5.0,
                 timeout_seconds: float = 8.0, extra_headers: dict[str, str] | None = None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout_seconds
        self._limiter = RateLimiter(max_requests_per_second)
        self._session = requests.Session()
        if extra_headers:
            self._session.headers.update(extra_headers)

    def _full_url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            # Still enforce same-origin: a module must not be able to pivot
            # this client at an arbitrary host via a crafted `path`.
            if not path.startswith(self.base_url):
                raise ValueError(f"Refusing cross-origin request from SafeClient scoped to {self.base_url}: {path}")
            return path
        return f"{self.base_url}/{path.lstrip('/')}"

    def request(self, method: str, path: str, **kwargs: Any) -> SafeResponse:
        self._limiter.wait()
        url = self._full_url(path)
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", False)
        try:
            resp = self._session.request(method, url, **kwargs)
            return SafeResponse(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                text=resp.text,
                elapsed_seconds=resp.elapsed.total_seconds(),
                url=resp.url,
                cookies=resp.cookies.get_dict(),
            )
        except requests.RequestException as exc:
            return SafeResponse(status_code=-1, headers={}, text="", elapsed_seconds=0.0,
                                 url=url, error=str(exc))

    def get(self, path: str, **kwargs: Any) -> SafeResponse:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> SafeResponse:
        return self.request("POST", path, **kwargs)

    def patch(self, path: str, **kwargs: Any) -> SafeResponse:
        return self.request("PATCH", path, **kwargs)

    def put(self, path: str, **kwargs: Any) -> SafeResponse:
        return self.request("PUT", path, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> SafeResponse:
        return self.request("DELETE", path, **kwargs)
