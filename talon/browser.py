"""Optional rendered crawling via Playwright (headless Chromium).

This is the ONE part of Talon that uses a third-party dependency, and it is
entirely optional. The stdlib crawler (talon/crawler.py) remains the default,
so `python3 -m talon` still runs with nothing installed. Render mode is opt-in
with `--render` and needs a one-time setup:

    pip install playwright
    python3 -m playwright install chromium

Why it exists: modern sites (React, Vue, Angular, Next, Svelte, …) ship a
near-empty HTML shell and build the real page with JavaScript in the browser.
The stdlib crawler reads raw HTML, so it sees that empty shell. Render mode
loads each in-scope page in a real browser, lets its JavaScript run, and reads
the resulting DOM for links and forms — the actual attack surface of the app.

Scope & safety:
  * Only in-scope origins are ever navigated to. A page's own subresources
    (its CDN JS, fonts, etc.) are allowed to load so the app can render; those
    are never crawled or tested, only the in-scope URLs are.
  * Rendering a page RUNS that site's JavaScript on your machine. Only point
    render mode at targets you are authorized to test.
  * The vulnerability checks still send raw HTTP requests, unchanged. The
    browser is used ONLY to discover what to test, so a finding's proof is
    still a plain, reproducible request.

The Playwright import is deliberately lazy (inside functions), so importing
`talon` without Playwright installed never fails.
"""
from __future__ import annotations

import json
import time
from collections import deque
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse

from .crawler import Crawler, Form, Surface
from .scope import Scope
from .web import DEFAULT_UA, WebClient

# Request types worth capturing: the data calls a page makes, not its assets.
_CAPTURE_TYPES = {"xhr", "fetch"}
_SKIP_TYPES = {"image", "stylesheet", "font", "media", "script", "manifest", "other"}
_MAX_CAPTURED = 80


class RenderError(RuntimeError):
    """Raised when render mode is requested but unavailable."""


def available() -> bool:
    """True if Playwright (the Python package) is importable."""
    try:
        import playwright  # noqa: F401
        return True
    except Exception:
        return False


def ensure_available() -> None:
    if not available():
        raise RenderError(
            "Render mode needs Playwright, which is not installed. Set it up with:\n"
            "    pip install playwright\n"
            "    python3 -m playwright install chromium\n"
            "Or run without --render to use the stdlib crawler."
        )


# Pull links and forms from the rendered DOM in one call. The browser has
# already resolved href/action to absolute URLs.
_EXTRACT_JS = r"""
() => {
  const links = Array.from(document.querySelectorAll('a[href]'))
    .map(a => a.href).filter(h => h.startsWith('http'));
  const forms = Array.from(document.querySelectorAll('form')).map(f => ({
    action: f.action || location.href,
    method: (f.getAttribute('method') || 'get').toLowerCase(),
    fields: Object.fromEntries(
      Array.from(f.querySelectorAll('input[name], textarea[name], select[name]'))
        .map(i => [i.name, i.value || '']))
  }));
  return { links, forms, url: location.href };
}
"""


class BrowserCrawler:
    """Same contract as Crawler.crawl, but renders each page in Chromium first.

    Produces the identical `Surface` objects the checks already consume, so the
    TEST phase does not change at all.
    """

    def __init__(
        self,
        client: WebClient,
        scope: Scope,
        *,
        max_pages: int = 25,
        max_depth: int = 2,
        rate: float = 0.5,
        wait_until: str = "domcontentloaded",
        settle_ms: int = 1500,
        nav_timeout_ms: int = 20000,
    ):
        self.client = client
        self.scope = scope
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.rate = rate
        self.wait_until = wait_until
        self.settle_ms = settle_ms
        self.nav_timeout_ms = nav_timeout_ms
        self.budget_exhausted = False      # parity with Crawler
        self.pages_rendered = 0
        self.captured = 0                  # API calls turned into surfaces
        self._seen_api: set[str] = set()
        self._last = 0.0
        # Reused only for its surface-building helpers (no requests are sent
        # through it here; the checks use `client` later for raw HTTP).
        self._h = Crawler(client, scope, max_pages=max_pages, max_depth=max_depth)

    def _throttle(self) -> None:
        wait = self.rate - (time.monotonic() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()

    def _capture(self, req, surfaces: dict) -> None:
        """Turn an observed fetch/XHR/form request into a testable Surface.

        Only in-scope requests that actually carry parameters (a query string or
        a parseable body) become surfaces; assets and empty calls are ignored.
        A page submitting a form, or JS calling its own API, is exactly the
        surface the DOM alone could not reveal.
        """
        try:
            rtype = req.resource_type
            method = (req.method or "GET").upper()
            is_form_post = method == "POST" and rtype in ("document", "other", "fetch", "xhr")
            if rtype not in _CAPTURE_TYPES and not is_form_post:
                return
            if rtype in _SKIP_TYPES and not is_form_post:
                return
            url = req.url
            if not self.scope.in_scope(url):
                return
            parsed = urlparse(url)
            base = urlunparse(parsed._replace(query="", fragment=""))

            if method == "GET":
                params = dict(parse_qsl(parsed.query, keep_blank_values=True))
                if not params:
                    return
                surface = Surface(url=base, params=params, method="GET")
                key = f"GET {base}?{','.join(sorted(params))}"
            else:
                body = req.post_data
                if not body:
                    return
                ctype = (req.headers or {}).get("content-type", "").lower()
                params, encoding = self._parse_body(body, ctype)
                if not params:
                    return
                surface = Surface(url=base, params=params, method="POST", encoding=encoding)
                key = f"POST[{encoding}] {base}?{','.join(sorted(params))}"

            if key in self._seen_api or len(self._seen_api) >= _MAX_CAPTURED:
                return
            self._seen_api.add(key)
            surfaces[key] = surface
            self.captured += 1
        except Exception:
            return  # capture is best-effort; never break the crawl

    @staticmethod
    def _parse_body(body: str, ctype: str) -> tuple[dict, str]:
        """(params, encoding) from a request body; {} if not injectable here."""
        if "application/json" in ctype or (body.lstrip()[:1] in "{["):
            try:
                obj = json.loads(body)
            except Exception:
                return {}, "json"
            if isinstance(obj, dict):
                # Only flat string/number fields are injectable in this version.
                flat = {k: ("" if v is None else str(v))
                        for k, v in obj.items() if isinstance(v, (str, int, float, bool))}
                return flat, "json"
            return {}, "json"
        if "x-www-form-urlencoded" in ctype or ("=" in body and "\n" not in body):
            return dict(parse_qsl(body, keep_blank_values=True)), "form"
        return {}, "form"

    def crawl(self, seeds: list[str]) -> list[Surface]:
        ensure_available()
        from playwright.sync_api import Error as PlaywrightError, sync_playwright

        seen: set[str] = set()
        surfaces: dict[str, Surface] = {}
        queue: deque[tuple[str, int]] = deque()
        for s in seeds:
            queue.append((s if "://" in s else f"https://{s}", 0))

        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            context = browser.new_context(user_agent=DEFAULT_UA)
            # Capture the data calls (fetch/XHR/form POST) the pages make, so the
            # API endpoints behind a JS app become part of the attack surface.
            context.on("request", lambda req: self._capture(req, surfaces))
            page = context.new_page()
            page.set_default_navigation_timeout(self.nav_timeout_ms)
            try:
                while queue and len(seen) < self.max_pages:
                    url, depth = queue.popleft()
                    norm = url.split("#")[0]
                    if norm in seen or not self.scope.in_scope(norm):
                        continue
                    seen.add(norm)
                    surface = self._h._surface_for(norm)
                    self._throttle()
                    try:
                        page.goto(norm, wait_until=self.wait_until)
                        if self.settle_ms:
                            page.wait_for_timeout(self.settle_ms)  # let SPA render
                        data = page.evaluate(_EXTRACT_JS)
                    except PlaywrightError:
                        surfaces.setdefault(Crawler._key(norm), surface)
                        continue
                    self.pages_rendered += 1

                    for f in data.get("forms", []):
                        action = urljoin(norm, f.get("action") or "") or norm
                        form = Form(action=action, method=f.get("method", "get"),
                                    fields=f.get("fields", {}) or {})
                        if self.scope.in_scope(form.action):
                            surface.forms.append(form)
                            self._h._register_form_surface(form, surfaces)
                    surfaces[Crawler._key(norm)] = surface

                    if depth >= self.max_depth:
                        continue
                    for href in data.get("links", []):
                        nxt = urljoin(norm, href)
                        if not nxt.startswith(("http://", "https://")):
                            continue
                        if self.scope.in_scope(nxt):
                            queue.append((nxt, depth + 1))
                            self._h._register_param_surface(nxt, surfaces)
            finally:
                context.close()
                browser.close()

        return list(surfaces.values())
