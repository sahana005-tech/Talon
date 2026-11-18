"""Lightweight tests (stdlib unittest). Run: python -m unittest -v"""
import html
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import talon.scope as scope_mod
from talon import browser
from talon.agent import Agent
from talon.llm import LLM
from talon.report import disclosure
from talon.web import WebClient
from talon.report.cvss import score
from talon.scope import Scope, ScopeError
from talon.checks.idor import _normalize, _ratio


class TestCvss(unittest.TestCase):
    def test_known_vectors(self):
        cases = {
            "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
            "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
            "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N": 6.5,
            "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N": 4.7,
            "AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N": 0.0,
        }
        for vec, expected in cases.items():
            self.assertAlmostEqual(score(vec).base_score, expected, places=1, msg=vec)

    def test_severity_bands(self):
        self.assertEqual(score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").severity, "Critical")
        self.assertEqual(score("AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N").severity, "Medium")


class TestScope(unittest.TestCase):
    def test_requires_authorization(self):
        s = Scope.from_targets(["https://example.com"], authorized=False)
        with self.assertRaises(ScopeError):
            s.require_authorized()

    def test_blocks_offscope_and_metadata(self):
        s = Scope.from_targets(["https://example.com"], authorized=True)
        self.assertTrue(s.in_scope("https://example.com/x"))
        self.assertFalse(s.in_scope("https://evil.com/x"))
        with self.assertRaises(ScopeError):
            s.check_host("169.254.169.254")

    def test_local_requires_optin(self):
        s = Scope.from_targets(["http://127.0.0.1:8000"], authorized=True, allow_local=False)
        with self.assertRaises(ScopeError):
            s.check_host("127.0.0.1")
        s2 = Scope.from_targets(["http://127.0.0.1:8000"], authorized=True, allow_local=True)
        s2.check_host("127.0.0.1")  # should not raise


class TestIdorSimilarity(unittest.TestCase):
    def test_same_object_high_ratio(self):
        a = "<h2>Alice</h2><p>recovery 11</p> id=1"
        b = "<h2>Alice</h2><p>recovery 11</p> id=1"
        self.assertGreaterEqual(_ratio(_normalize(a, "1"), _normalize(b, "1")), 0.9)

    def test_distinct_objects_low_ratio(self):
        a = "<h2>Alice Anand</h2><p>recovery code 11-AA-77</p>"
        b = "<h2>Bob Balan</h2><p>recovery code 22-BB-88</p>"
        self.assertLess(_ratio(_normalize(a, "1"), _normalize(b, "2")), 0.9)


# --- end-to-end tests against a tiny in-process app -------------------------
_OWNER = {"1": "alice", "2": "bob"}
_HOME = """<html><body>
<a href="/article?id=5">public article</a>
<a href="/list?page=2">page two</a>
<a href="/secure?id=2">owner-only record</a>
<a href="/leaky?id=1">leaky record</a>
<a href="/text?q=x">text</a>
<a href="/safe?q=x">safe</a>
<a href="/attr?q=x">attr</a>
<a href="/js?q=x">js</a>
<form action="/find" method="get"><input name="term"></form>
<form action="/comment" method="post"><input name="body"></form>
</body></html>"""


def _enc_angles(s):  # encode only < > (leaving quotes raw) — a common half-fix
    return s.replace("<", "&lt;").replace(">", "&gt;")


class _App(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query, keep_blank_values=True)
        oid = q.get("id", [""])[0]
        term = q.get("q", q.get("term", [""]))[0]
        cookie = self.headers.get("Cookie", "")
        user = cookie.split("session=")[-1] if "session=" in cookie else None
        if u.path == "/":
            return self._send(200, _HOME)
        if u.path == "/.well-known/security.txt":
            return self._send(200, "Contact: mailto:sec@example.test\n", "text/plain")
        if u.path == "/article":          # public: same for everyone, no auth
            if oid != "5":
                return self._send(404, "<h1>404 not found</h1>")
            return self._send(200, "<html><body><p>Public article about bread.</p></body></html>")
        if u.path == "/list":             # public pagination
            return self._send(200, "<html><body><p>widget, gadget, sprocket</p></body></html>")
        if u.path in ("/secure", "/leaky"):
            if user not in ("alice", "bob"):
                return self._send(401, "<h1>401 log in</h1>")
            if oid not in _OWNER:
                return self._send(404, "<h1>404 not found</h1>")
            if u.path == "/secure" and _OWNER[oid] != user:
                return self._send(403, "<h1>403 forbidden</h1>")
            return self._send(200, f"<html><body><h2>Private record of "
                                   f"{_OWNER[oid]}: secret zz-99-qq</h2></body></html>")
        # --- XSS contexts ---
        if u.path == "/text":             # VULN: reflected unescaped in HTML text
            return self._send(200, f"<html><body><p>{term}</p></body></html>")
        if u.path == "/safe":             # correctly escaped -> not exploitable
            return self._send(200, f"<html><body><p>{html.escape(term)}</p></body></html>")
        if u.path == "/attr":             # VULN: <> encoded, quotes raw in attribute
            return self._send(200, f'<html><body><input value="{_enc_angles(term)}"></body></html>')
        if u.path == "/js":               # VULN: <> encoded, quotes raw in JS string
            return self._send(200, f"<html><body><script>var s='{_enc_angles(term)}';</script></body></html>")
        if u.path == "/find":             # GET form target: reflected unescaped
            return self._send(200, f"<html><body><p>Results: {term}</p></body></html>")
        return self._send(404, "<h1>404</h1>")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n).decode()
        val = parse_qs(body).get("body", [""])[0]
        if urlparse(self.path).path == "/comment":   # VULN: reflected unescaped
            return self._send(200, f"<html><body><p>Saved: {val}</p></body></html>")
        return self._send(404, "<h1>404</h1>")

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class TestEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), _App)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _scan(self, **kw):
        scope = Scope.from_targets([self.base], authorized=True, allow_local=True)
        ids = [{"label": n, "headers": {"Cookie": f"session={n}"}} for n in ("alice", "bob")]
        agent = Agent(scope, checks=["idor"], identities=ids, rate=0, **kw)
        return agent.scan([self.base])

    def test_idor_only_flags_private_unprotected_object(self):
        result = self._scan()
        flagged = {f.url.rsplit("/", 1)[-1] for f in result.validated}
        # Public content, pagination and a correctly protected record are NOT IDORs.
        self.assertEqual(flagged, {"leaky"})
        self.assertFalse(result.budget_exhausted)

    def test_budget_exhaustion_returns_partial_result(self):
        result = self._scan(max_requests=2)   # used to raise BudgetExceeded
        self.assertTrue(result.budget_exhausted)
        self.assertEqual(result.requests_made, 2)

    def test_blocked_target_is_an_error_not_a_clean_scan(self):
        scope = Scope.from_targets([self.base], authorized=True, allow_local=False)
        with self.assertRaises(ScopeError):
            scope.check_targets([self.base])
        with self.assertRaises(ScopeError):
            Agent(scope, rate=0).scan([self.base])

    def test_security_txt_found_on_target_port(self):
        scope = Scope.from_targets([self.base], authorized=True, allow_local=True)
        client = WebClient(scope, rate=0)
        fields = disclosure.find_security_txt(client, "127.0.0.1", [self.base])
        self.assertIsNotNone(fields)
        self.assertEqual(fields["contact"], ["mailto:sec@example.test"])
        self.assertTrue(fields["_source"].startswith(self.base))

    def test_xss_validates_by_context_and_covers_forms(self):
        scope = Scope.from_targets([self.base], authorized=True, allow_local=True)
        agent = Agent(scope, checks=["reflected-xss"], rate=0)
        result = agent.scan([self.base])
        validated = {f.url.rsplit("/", 1)[-1] for f in result.validated}
        probable = {f.url.rsplit("/", 1)[-1] for f in result.probable}
        # Quote-only attribute and JS-string breakouts are proven (fix 7); the GET
        # form field and the POST form field are reached (fix 6); the properly
        # escaped endpoint stays probable, never validated.
        self.assertEqual(validated, {"text", "attr", "js", "find", "comment"})
        self.assertIn("safe", probable)
        self.assertNotIn("safe", validated)

    def test_post_form_poc_is_a_post(self):
        scope = Scope.from_targets([self.base], authorized=True, allow_local=True)
        agent = Agent(scope, checks=["reflected-xss"], rate=0)
        result = agent.scan([self.base])
        comment = next(f for f in result.validated if f.url.endswith("/comment"))
        self.assertTrue(comment.poc.startswith("POST "))
        self.assertIn("body:", comment.poc)


class TestScopeOrigin(unittest.TestCase):
    def test_scope_is_per_origin_not_per_host(self):
        s = Scope.from_targets(["http://127.0.0.1:8000"], authorized=True, allow_local=True)
        self.assertTrue(s.in_scope("http://127.0.0.1:8000/x"))
        # A different port on the same host is out of scope.
        self.assertFalse(s.in_scope("http://127.0.0.1:8011/x"))
        self.assertFalse(s.in_scope("http://127.0.0.1:22/x"))

    def test_dns_rebinding_to_local_is_blocked(self):
        orig = scope_mod.socket.getaddrinfo
        scope_mod.socket.getaddrinfo = lambda *a, **k: [(2, 1, 6, "", ("127.0.0.1", 0))]
        try:
            s = Scope.from_targets(["http://rebind.example"], authorized=True, allow_local=False)
            with self.assertRaises(ScopeError):
                s.check_url("http://rebind.example/")
        finally:
            scope_mod.socket.getaddrinfo = orig

    def test_metadata_blocked_even_with_allow_local(self):
        orig = scope_mod.socket.getaddrinfo
        scope_mod.socket.getaddrinfo = lambda *a, **k: [(2, 1, 6, "", ("169.254.169.254", 0))]
        try:
            s = Scope.from_targets(["http://meta.example"], authorized=True, allow_local=True)
            with self.assertRaises(ScopeError):
                s.check_url("http://meta.example/")
        finally:
            scope_mod.socket.getaddrinfo = orig


_SHELL = """<!doctype html><html><body><div id=app>Loading…</div><script>
setTimeout(function(){document.getElementById('app').innerHTML =
  '<a href="/search?q=hi">s</a>';}, 20);
</script></body></html>"""


class _SpaApp(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        u = urlparse(self.path); q = parse_qs(u.query, keep_blank_values=True)
        if u.path == "/":
            body = _SHELL
        elif u.path == "/search":
            body = f"<html><body><p>{q.get('q', [''])[0]}</p></body></html>"   # VULN: unescaped
        else:
            body = "<h1>404</h1>"
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers(); self.wfile.write(data)


@unittest.skipUnless(browser.available(), "Playwright not installed; render mode skipped")
class TestRenderMode(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), _SpaApp)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close()

    def test_render_finds_js_built_surface_that_stdlib_misses(self):
        scope = Scope.from_targets([self.base], authorized=True, allow_local=True)
        # Stdlib crawl sees only the empty shell: no link, nothing to test.
        plain = Agent(scope, checks=["reflected-xss"], rate=0).scan([self.base])
        self.assertEqual(len(plain.validated), 0)
        # Render mode runs the JS, discovers /search, and validates the XSS.
        rendered = Agent(scope, checks=["reflected-xss"], rate=0, render=True,
                         render_wait=400).scan([self.base])
        self.assertGreaterEqual(rendered.rendered, 1)
        self.assertEqual({f.url.rsplit("/", 1)[-1] for f in rendered.validated}, {"search"})


class TestLlmProvider(unittest.TestCase):
    def test_openai_compatible_uses_base_url(self):
        posted = {}
        llm = LLM("openai-compat/some-model", api_key="k", base_url="https://host.example/v1")
        self.assertTrue(llm.enabled)
        llm._post = lambda url, h, p: (posted.update(url=url, auth=h.get("authorization")),
                                       {"choices": [{"message": {"content": "hi"}}]})[1]
        self.assertEqual(llm.complete("s", "u"), "hi")
        self.assertEqual(posted["url"], "https://host.example/v1/chat/completions")
        self.assertEqual(posted["auth"], "Bearer k")

    def test_openai_compat_without_base_url_is_a_safe_noop(self):
        llm = LLM("openai-compat/some-model", api_key="k")  # no base URL
        self.assertIsNone(llm.complete("s", "u"))


if __name__ == "__main__":
    unittest.main()
