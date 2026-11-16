"""Same-origin crawler + attack-surface inventory.

Produces a list of `Surface` objects — each is a URL plus the injectable
inputs on it (query parameters and HTML form fields). The checks consume
surfaces; they do not crawl themselves.

Parsing uses the stdlib html.parser, so no third-party dependency.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urldefrag, urljoin, urlparse, urlencode, urlunparse

from .scope import Scope
from .web import BudgetExceeded, WebClient


@dataclass
class Form:
    action: str
    method: str
    fields: dict[str, str]  # name -> default value


@dataclass
class Surface:
    url: str                       # URL without query string
    params: dict[str, str] = field(default_factory=dict)   # params + values
    forms: list[Form] = field(default_factory=list)
    method: str = "GET"            # "GET" (query) or "POST" (form body)

    def with_param(self, name: str, value: str) -> str:
        """Build a URL identical to this surface but with one param overridden.

        For GET the override lands in the query string; for POST the body is
        sent separately (see `mutate`), and this returns the bare action URL.
        """
        if self.method == "POST":
            return self.url
        merged = dict(self.params)
        merged[name] = value
        parsed = urlparse(self.url)
        return urlunparse(parsed._replace(query=urlencode(merged)))

    def mutate(self, name: str, value: str) -> dict:
        """Return kwargs for WebClient.request that set `name` to `value`.

        GET -> the value goes in the query string. POST -> it goes in a urlencoded
        form body, with the matching Content-Type.
        """
        merged = dict(self.params)
        merged[name] = value
        if self.method == "POST":
            return {
                "url": self.url,
                "method": "POST",
                "data": urlencode(merged).encode(),
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            }
        return {"url": self.with_param(name, value)}

    def shown(self, name: str, value: str) -> str:
        """Human-readable one-line form of that request, for PoCs/evidence."""
        if self.method == "POST":
            body = urlencode({**self.params, name: value})
            return f"POST {self.url}\n  body: {body}"
        return f"GET {self.with_param(name, value)}"

    def curl(self, name: str, value: str) -> str:
        if self.method == "POST":
            body = urlencode({**self.params, name: value})
            return (f"curl -sS -i -X POST "
                    f"-H 'Content-Type: application/x-www-form-urlencoded' "
                    f"--data {body!r} {self.url!r}")
        return f"curl -sS -i {self.with_param(name, value)!r}"


class _LinkFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.forms: list[Form] = []
        self._cur: Form | None = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "form":
            self._cur = Form(action=a.get("action", ""), method=a.get("method", "get").lower(), fields={})
        elif tag in ("input", "textarea", "select") and self._cur is not None:
            name = a.get("name")
            if name:
                self._cur.fields[name] = a.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None


class Crawler:
    def __init__(self, client: WebClient, scope: Scope, *, max_pages: int = 25, max_depth: int = 2):
        self.client = client
        self.scope = scope
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.budget_exhausted = False

    def crawl(self, seeds: list[str]) -> list[Surface]:
        seen: set[str] = set()
        surfaces: dict[str, Surface] = {}
        queue: deque[tuple[str, int]] = deque()

        for s in seeds:
            url = s if "://" in s else f"https://{s}"
            queue.append((url, 0))

        while queue and len(seen) < self.max_pages:
            url, depth = queue.popleft()
            url, _ = urldefrag(url)
            norm = url.split("#")[0]
            if norm in seen or not self.scope.in_scope(norm):
                continue
            seen.add(norm)

            surface = self._surface_for(norm)
            try:
                resp = self.client.request(norm)
            except BudgetExceeded:
                # Stop crawling but keep what we mapped so far.
                self.budget_exhausted = True
                break
            if resp.error or resp.status == 0:
                surfaces.setdefault(self._key(norm), surface)
                continue

            ctype = (resp.header("content-type") or "").lower()
            if "html" not in ctype and resp.body.lstrip()[:1] not in ("<",):
                surfaces.setdefault(self._key(norm), surface)
                continue

            parser = _LinkFormParser()
            try:
                parser.feed(resp.body)
            except Exception:
                pass

            # Record forms on this page and turn each into a testable surface.
            for f in parser.forms:
                f.action = urljoin(norm, f.action) if f.action else norm
                if self.scope.in_scope(f.action):
                    surface.forms.append(f)
                    self._register_form_surface(f, surfaces)
            surfaces[self._key(norm)] = surface

            if depth >= self.max_depth:
                continue
            for href in parser.links:
                nxt = urljoin(norm, href)
                if not nxt.startswith(("http://", "https://")):
                    continue
                if self.scope.in_scope(nxt):
                    queue.append((nxt, depth + 1))
                    # Capture a surface for parameterised links even if we don't recurse.
                    self._register_param_surface(nxt, surfaces)

        return list(surfaces.values())

    def _surface_for(self, url: str) -> Surface:
        parsed = urlparse(url)
        base = urlunparse(parsed._replace(query=""))
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        return Surface(url=base if not params else url_with(base, params), params=params)

    def _register_form_surface(self, form: Form, surfaces: dict[str, Surface]) -> None:
        """Expose a crawled form as a Surface so the checks can probe its fields.

        GET forms become an ordinary query-param surface. POST forms become a
        POST surface (only the reflected-XSS check probes those; the agent skips
        state-changing POSTs for redirect/IDOR)."""
        if not form.fields:
            return
        params = {k: (v or "1") for k, v in form.fields.items()}
        parsed = urlparse(form.action.split("#")[0])
        base = urlunparse(parsed._replace(query="", fragment=""))
        method = "POST" if form.method == "post" else "GET"
        names = ",".join(sorted(params))
        key = f"{method} {parsed.scheme}://{parsed.netloc}{parsed.path}?{names}"
        if key in surfaces:
            return
        if method == "GET":
            surfaces[key] = Surface(url=url_with(base, params), params=params)
        else:
            surfaces[key] = Surface(url=base, params=params, method="POST")

    def _register_param_surface(self, url: str, surfaces: dict[str, Surface]) -> None:
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        if not params:
            return
        key = self._key(url)
        if key not in surfaces:
            base = urlunparse(parsed._replace(query=""))
            surfaces[key] = Surface(url=url_with(base, params), params=params)

    @staticmethod
    def _key(url: str) -> str:
        parsed = urlparse(url)
        param_names = ",".join(sorted(dict(parse_qsl(parsed.query)).keys()))
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param_names}"


def url_with(base: str, params: dict[str, str]) -> str:
    parsed = urlparse(base)
    return urlunparse(parsed._replace(query=urlencode(params)))
