"""A deliberately vulnerable *single-page-app* demo for exercising --render.

Run:  python3 demo/spa_app.py   (serves on 127.0.0.1:8020)

Unlike demo/vuln_app.py, the home page is an empty shell: the links and the
form are built by JavaScript AFTER load, the way a React/Vue/Angular app works.
So the stdlib crawler (raw HTML) sees nothing to test, while `--render` runs
the JS, discovers /search and /go, and the checks validate them.

Compare:
    python3 -m talon -t http://127.0.0.1:8020 --authorize --allow-local
    python3 -m talon -t http://127.0.0.1:8020 --authorize --allow-local --render

DO NOT expose this to a network. Local demonstration only.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

# The shell holds no links/forms in its HTML — JS injects them after load.
SHELL = """<!doctype html><html><head><title>SPA demo</title></head>
<body><div id="app">Loading…</div>
<script>
  // Simulate a client-rendered app: build the UI after a tick.
  setTimeout(function () {
    document.getElementById('app').innerHTML =
      '<h1>Dashboard</h1>' +
      '<a href="/search?q=hello">search</a> ' +
      '<a href="/go?url=/search?q=hi">open redirector</a>' +
      '<form action="/find" method="get"><input name="term"><button>go</button></form>';
  }, 50);
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query, keep_blank_values=True)
        if u.path == "/":
            return self._html(200, SHELL)
        if u.path in ("/search", "/find"):
            term = q.get("q", q.get("term", [""]))[0]
            # VULN: reflected without encoding
            return self._html(200, f"<!doctype html><html><body><h2>Results for: "
                                   f"{term}</h2><p>No results.</p></body></html>")
        if u.path == "/go":
            dest = q.get("url", [""])[0]
            self.send_response(302)          # VULN: unvalidated redirect
            self.send_header("Location", dest)
            self.end_headers()
            return
        return self._html(404, "<h1>404</h1>")

    def _html(self, code, body):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8020), Handler).serve_forever()
