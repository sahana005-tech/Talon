"""Minimal HTTP client built on the standard library.

Zero third-party dependencies so Talon runs anywhere Python 3.9+ is installed.
This is Talon's analogue of Strix's logging HTTP proxy: every request/response
pair is recorded so a finding can cite the exact traffic that proves it.

Key behaviours:
  * Redirects are NOT followed automatically — the open-redirect check needs to
    inspect the raw 3xx Location header.
  * A global request budget and per-request delay keep the scan polite.
  * Every host is re-checked against the Scope before a socket is opened.
"""
from __future__ import annotations

import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from .scope import Scope, ScopeError

DEFAULT_UA = "Talon/0.1 (+authorized-security-testing)"


@dataclass
class Response:
    url: str
    status: int
    headers: dict[str, str]
    body: str
    elapsed_ms: int
    error: str | None = None

    def header(self, name: str) -> str | None:
        name = name.lower()
        for k, v in self.headers.items():
            if k.lower() == name:
                return v
        return None


@dataclass
class Exchange:
    """A recorded request/response pair for evidence."""
    method: str
    url: str
    request_headers: dict[str, str]
    response: Response

    def as_curl(self) -> str:
        parts = [f"curl -sS -i -X {self.method}"]
        for k, v in self.request_headers.items():
            if k.lower() == "user-agent":
                continue
            parts.append(f"-H {k}: {v!r}")
        parts.append(f"{self.url!r}")
        return " ".join(parts)


class BudgetExceeded(Exception):
    pass


class WebClient:
    def __init__(
        self,
        scope: Scope,
        *,
        rate: float = 0.5,
        timeout: float = 15.0,
        max_requests: int = 500,
        user_agent: str = DEFAULT_UA,
    ):
        self.scope = scope
        self.rate = rate
        self.timeout = timeout
        self.max_requests = max_requests
        self.user_agent = user_agent
        self.count = 0
        self.log: list[Exchange] = []
        self._last = 0.0
        # Opener that never follows redirects, so we can see Location headers.
        self._opener = urllib.request.build_opener(_NoRedirect())

    def _throttle(self) -> None:
        wait = self.rate - (time.monotonic() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()

    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        data: bytes | None = None,
    ) -> Response:
        self.scope.check_url(url)  # raises ScopeError if origin is out of scope

        if self.count >= self.max_requests:
            raise BudgetExceeded(
                f"request budget of {self.max_requests} exhausted"
            )
        self._throttle()
        self.count += 1

        req_headers = {"User-Agent": self.user_agent}
        if headers:
            req_headers.update(headers)
        req = urllib.request.Request(url, data=data, headers=req_headers, method=method)

        start = time.monotonic()
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                raw = resp.read()
                response = Response(
                    url=resp.geturl(),
                    status=resp.status,
                    headers=dict(resp.headers.items()),
                    body=_decode(raw),
                    elapsed_ms=int((time.monotonic() - start) * 1000),
                )
        except urllib.error.HTTPError as e:
            # HTTPError is still a valid response we want to inspect (incl. 3xx
            # captured by the no-redirect handler, 4xx, 5xx).
            raw = e.read() if hasattr(e, "read") else b""
            response = Response(
                url=url,
                status=e.code,
                headers=dict(e.headers.items()) if e.headers else {},
                body=_decode(raw),
                elapsed_ms=int((time.monotonic() - start) * 1000),
            )
        except (urllib.error.URLError, OSError, ScopeError) as e:
            response = Response(
                url=url, status=0, headers={}, body="",
                elapsed_ms=int((time.monotonic() - start) * 1000),
                error=str(e),
            )

        self.log.append(
            Exchange(method=method, url=url, request_headers=req_headers, response=response)
        )
        return response


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Turn 3xx responses into HTTPError so the caller sees the Location header."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802,D401
        return None


def _decode(raw: bytes) -> str:
    for enc in ("utf-8", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")
