"""Open Redirect check.

Strategy (validation-first):
  1. Identify parameters that commonly carry redirect targets (next, url,
     return, dest, redirect, continue, ...), plus any param whose value
     already looks like a URL or path.
  2. Inject a benign external canary host.
  3. Request WITHOUT following redirects. If the server answers 3xx with a
     Location header pointing at the attacker-controlled external host, the
     redirect is open — that Location header IS the proof.

We only treat header-based redirects as validated. Body/meta/JS redirects are
reported as "probable" for manual review.
"""
from __future__ import annotations

from urllib.parse import urlparse

from ..crawler import Surface
from .base import Check, Finding

# Benign, clearly-external marker. Using example.com per RFC 2606.
_CANARY_HOST = "talon-oredir.example.com"
_CANARY = f"https://{_CANARY_HOST}/poc"

_REDIRECT_PARAMS = {
    "next", "url", "redirect", "redirect_uri", "redirect_url", "return",
    "returnto", "return_to", "returnurl", "dest", "destination", "continue",
    "goto", "go", "r", "u", "target", "forward", "callback", "out", "link",
}

# CVSS 3.1: network, low complexity, no privs, user interaction, scope changed,
# low integrity impact (phishing / token leakage vector), no confidentiality.
_VECTOR = "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N"


class OpenRedirectCheck(Check):
    id = "open-redirect"
    name = "Open Redirect"
    cwe = "CWE-601"

    def run(self, surface: Surface) -> list[Finding]:
        findings: list[Finding] = []
        if surface.method != "GET":
            return findings  # redirect probing is GET-only; never submit POST forms
        for param, value in surface.params.items():
            if not self._is_candidate(param, value):
                continue
            finding = self._test_param(surface, param)
            if finding:
                findings.append(finding)
        return findings

    def _is_candidate(self, param: str, value: str) -> bool:
        if param.lower() in _REDIRECT_PARAMS:
            return True
        v = value.lower()
        return v.startswith(("http://", "https://", "//", "/")) or "://" in v

    def _test_param(self, surface: Surface, param: str) -> Finding | None:
        test_url = surface.with_param(param, _CANARY)
        resp = self.client.request(test_url)
        if resp.error:
            return None

        location = resp.header("location")
        if 300 <= resp.status < 400 and location:
            loc_host = urlparse(location if "://" in location else f"https:{location}" if location.startswith("//") else location).hostname
            if loc_host and loc_host.lower() == _CANARY_HOST:
                return Finding(
                    check_id=self.id,
                    name=self.name,
                    url=surface.url.split("?")[0],
                    parameter=param,
                    cvss_vector=_VECTOR,
                    cwe=self.cwe,
                    confidence="validated",
                    description=(
                        f"The '{param}' parameter controls the redirect "
                        f"destination without validating it against an allow-list. "
                        f"An attacker can send victims a trusted-looking link that "
                        f"silently forwards them to an arbitrary external site "
                        f"(phishing, OAuth token theft)."
                    ),
                    evidence=(
                        f"Request to {test_url} returned HTTP {resp.status} with "
                        f"Location: {location} — the server redirected to the "
                        f"attacker-controlled host '{_CANARY_HOST}'."
                    ),
                    poc=(
                        f"GET {test_url}\n"
                        f"-> HTTP {resp.status}, Location: {location}\n\n"
                        f"{_curl(test_url)}"
                    ),
                    remediation=(
                        "Do not place user input directly in the redirect target. "
                        "Validate against a server-side allow-list of permitted "
                        "paths/hosts, or map an opaque key to the destination. "
                        "If external redirects are required, show an interstitial."
                    ),
                    exchanges=[self.client.log[-1]],
                )

        # Reflected into body as a would-be redirect but not via Location header.
        if _CANARY_HOST in resp.body:
            return Finding(
                check_id=self.id, name=self.name, url=surface.url.split("?")[0],
                parameter=param, cvss_vector=_VECTOR, cwe=self.cwe,
                confidence="probable",
                description=(
                    f"The '{param}' value appears in the response body in a "
                    f"redirect-like context (meta refresh / JS). Possible "
                    f"client-side open redirect — needs manual confirmation."
                ),
                evidence=f"Canary host '{_CANARY_HOST}' present in body, no 3xx Location.",
                poc="(not validated — manual review required)",
                remediation="Validate redirect targets against an allow-list.",
                exchanges=[self.client.log[-1]],
            )
        return None


def _curl(url: str) -> str:
    return f"curl -sS -i {url!r}   # note: no -L, so the 3xx Location is visible"
