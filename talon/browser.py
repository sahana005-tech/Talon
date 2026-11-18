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

import time
from collections import deque
from urllib.parse import urljoin

from .crawler import Crawler, Form, Surface
from .scope import Scope
from .web import DEFAULT_UA, WebClient


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
        self._last = 0.0
        # Reused only for its surface-building helpers (no requests are sent
        # through it here; the checks use `client` later for raw HTTP).
        self._h = Crawler(client, scope, max_pages=max_pages, max_depth=max_depth)

    def _throttle(self) -> None:
        wait = self.rate - (time.monotonic() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()

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
