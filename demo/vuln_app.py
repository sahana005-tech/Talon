"""A deliberately vulnerable demo app for exercising Talon LOCALLY.

Run:  python demo/vuln_app.py   (serves on 127.0.0.1:8000)

It intentionally contains one of each vulnerability class Talon detects:
  * /search?q=       reflected XSS (q echoed unescaped)
  * /go?url=         open redirect (302 Location: <url>)
  * /profile?id=N    IDOR (returns any user's private record to any session)

DO NOT expose this to a network. It exists only so you can see a real,
validated Talon report without touching anyone else's system.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

# Fake "database" of private records, keyed by object id.
USERS = {
    "1": {"owner": "alice", "name": "Alice Anand", "email": "alice@example.com",
          "note": "Private profile for user 1 — recovery code 11-AA-77."},
    "2": {"owner": "bob", "name": "Bob Balan", "email": "bob@example.com",
          "note": "Private profile for user 2 — recovery code 22-BB-88."},
    "3": {"owner": "carol", "name": "Carol Costa", "email": "carol@example.com",
          "note": "Private profile for user 3 — recovery code 33-CC-99."},
}
VALID_SESSIONS = {"alice", "bob", "carol"}

HOME = """<!doctype html><html><head><title>Vulnerable Demo</title></head>
<body><h1>Demo app</h1>
<ul>
  <li><a href="/search?q=hello">search</a></li>
  <li><a href="/go?url=/search?q=hi">redirector</a></li>
  <li><a href="/profile?id=1">my profile</a></li>
</ul></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # keep demo output quiet
        pass

    def _session(self):
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            if part.strip().startswith("session="):
                return part.strip()[len("session="):]
        return None

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query, keep_blank_values=True)

        if u.path == "/":
            return self._html(200, HOME)

        if u.path == "/search":
            term = q.get("q", [""])[0]
            # VULN: reflected without encoding
            body = f"<!doctype html><html><body><h2>Results for: {term}</h2>" \
                   f"<p>No results.</p></body></html>"
            return self._html(200, body)

        if u.path == "/go":
            dest = q.get("url", [""])[0]
            # VULN: unvalidated redirect
            self.send_response(302)
            self.send_header("Location", dest)
            self.end_headers()
            return

        if u.path == "/profile":
            if self._session() not in VALID_SESSIONS:
                return self._html(401, "<h1>401 — log in</h1>")
            oid = q.get("id", [""])[0]
            rec = USERS.get(oid)
            if not rec:
                return self._html(404, "<h1>404 — no such profile</h1>")
            # VULN: no ownership check — any valid session reads any record
            body = (f"<!doctype html><html><body><h2>{rec['name']}</h2>"
                    f"<p>Email: {rec['email']}</p>"
                    f"<p>{rec['note']}</p></body></html>")
            return self._html(200, body)

        return self._html(404, "<h1>404</h1>")

    def _html(self, code, body):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8000), Handler).serve_forever()
