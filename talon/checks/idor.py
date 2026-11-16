"""IDOR / Broken Object-Level Authorization check.

This is the hardest class to validate automatically because it is fundamentally
about *authorization*, which requires identity. Talon handles it honestly:

  * With TWO identities (recommended): we prove it. Identity B requests an
    object that belongs to identity A. If B receives A's object-specific
    content (and the endpoint demonstrably distinguishes valid vs bogus IDs),
    object-level authorization is broken. The cross-user response IS the proof.
    An unauthenticated control request guards against false positives: if the
    same object is served with no credentials at all, it is public content,
    not an IDOR, and nothing is reported.

  * With ONE or ZERO identities: we can only *suggest*. We probe neighbouring
    object IDs; if they return distinct, substantive objects with no
    authorization barrier, we report "probable" enumeration for manual review.
    No PoC is claimed.

Identities come from the run context:
    context["identities"] = [{"label": "alice", "headers": {"Cookie": "..."}}, ...]
"""
from __future__ import annotations

import difflib
import re

from ..crawler import Surface
from .base import Check, Finding

_ID_PARAM_HINTS = {
    "id", "uid", "userid", "user_id", "user", "account", "account_id", "aid",
    "order", "order_id", "orderid", "invoice", "invoice_id", "doc", "docid",
    "document", "file", "fileid", "pid", "no", "number", "ref", "record",
}

# CVSS 3.1: network, low complexity, low privs (authenticated user), no UI,
# scope unchanged, high confidentiality impact (read another user's data).
_VECTOR = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"


class IdorCheck(Check):
    id = "idor"
    name = "Insecure Direct Object Reference (BOLA)"
    cwe = "CWE-639"

    def run(self, surface: Surface) -> list[Finding]:
        findings: list[Finding] = []
        if surface.method != "GET":
            return findings  # IDOR is probed via GET; never submit POST forms
        identities = self.context.get("identities") or []
        for param, value in surface.params.items():
            if not self._looks_like_id(param, value):
                continue
            if len(identities) >= 2:
                f = self._validate_cross_user(surface, param, value, identities)
            else:
                f = self._probe_enumeration(surface, param, value, identities)
            if f:
                findings.append(f)
        return findings

    @staticmethod
    def _looks_like_id(param: str, value: str) -> bool:
        if not value.isdigit():
            return False
        # Only parameters that are named like object references. A bare numeric
        # value is not enough: page=2, limit=10, year=2024 are not object ids.
        name = param.lower()
        return (name in _ID_PARAM_HINTS or name.endswith(("_id", "-id"))
                or param.endswith(("Id", "ID")))

    # --- validated path: two identities ------------------------------------
    def _validate_cross_user(self, surface, param, value, identities) -> Finding | None:
        a, b = identities[0], identities[1]
        v = int(value)
        url = surface.with_param(param, str(v))

        a_resp = self.client.request(url, headers=a["headers"])
        b_resp = self.client.request(url, headers=b["headers"])
        b_exchange = self.client.log[-1]   # the proof: non-owner receiving the object
        if not (a_resp.status == 200 and b_resp.status == 200):
            return None
        if len(b_resp.body.strip()) < 16:
            return None

        bogus_id = str(v + 7_000_003)
        bogus_resp = self.client.request(surface.with_param(param, bogus_id), headers=b["headers"])
        # Control: the same request with NO credentials. If that also returns
        # the object, it is public content and there is nothing to authorize.
        anon_resp = self.client.request(url)

        a_norm = _normalize(a_resp.body, value)
        b_norm = _normalize(b_resp.body, value)
        bogus_norm = _normalize(bogus_resp.body, bogus_id)

        same_object = _ratio(a_norm, b_norm) >= 0.90
        distinguishes = (bogus_resp.status != 200) or (_ratio(b_norm, bogus_norm) < 0.75)
        is_public = (anon_resp.status == 200 and
                     _ratio(_normalize(anon_resp.body, value), b_norm) >= 0.90)
        anon_note = (f"HTTP {anon_resp.status}" if anon_resp.status != 200
                     else "HTTP 200 with different content")

        if same_object and distinguishes and not is_public:
            return Finding(
                check_id=self.id, name=self.name, url=surface.url.split("?")[0],
                parameter=param, cvss_vector=_VECTOR, cwe=self.cwe,
                confidence="validated",
                description=(
                    f"The object referenced by '{param}={value}' is protected "
                    f"(an unauthenticated request is refused) yet is returned "
                    f"identically to both '{a['label']}' and '{b['label']}'. "
                    f"Unless this object is intentionally shared between those "
                    f"accounts, the endpoint enforces no object-level "
                    f"authorization, so any authenticated user can read other "
                    f"users' records by changing the identifier (IDOR/BOLA)."
                ),
                evidence=(
                    f"'{a['label']}' and '{b['label']}' received equivalent "
                    f"object-specific responses for {param}={value} "
                    f"(similarity {_ratio(a_norm, b_norm):.2f}). A bogus id "
                    f"({bogus_id}) returned HTTP {bogus_resp.status} / distinct "
                    f"content, so the response is object-specific, not a generic "
                    f"page. The same request without credentials returned "
                    f"{anon_note}, so the object is not public."
                ),
                poc=(
                    f"As user '{b['label']}', request:\n"
                    f"  GET {url}\n"
                    f"  -> HTTP 200 with the same record '{a['label']}' receives.\n"
                    f"Without credentials the same URL returns {anon_note}.\n\n"
                    f"{_curl(url, b['headers'])}"
                ),
                remediation=(
                    "Enforce an authorization check on every object access: "
                    "verify the authenticated principal owns or may access the "
                    "requested object before returning it. Do not rely on the "
                    "identifier being unguessable."
                ),
                exchanges=[b_exchange],
            )
        return None

    # --- probable path: enumeration signal ---------------------------------
    def _probe_enumeration(self, surface, param, value, identities) -> Finding | None:
        headers = identities[0]["headers"] if identities else None
        v = int(value)
        base = self.client.request(surface.with_param(param, str(v)), headers=headers)
        if base.status != 200 or len(base.body.strip()) < 16:
            return None
        neighbours = [v - 1, v + 1]
        distinct_hits = 0
        for n in neighbours:
            if n < 0:
                continue
            r = self.client.request(surface.with_param(param, str(n)), headers=headers)
            if r.status == 200 and len(r.body.strip()) >= 16:
                if _ratio(_normalize(base.body, str(v)), _normalize(r.body, str(n))) < 0.98:
                    distinct_hits += 1
        if distinct_hits >= 1:
            ident_note = (
                f"as '{identities[0]['label']}'" if identities
                else "with no authentication"
            )
            return Finding(
                check_id=self.id, name=self.name, url=surface.url.split("?")[0],
                parameter=param, cvss_vector=_VECTOR, cwe=self.cwe,
                confidence="probable",
                description=(
                    f"Numeric reference '{param}' appears directly enumerable "
                    f"{ident_note}: adjacent identifiers return distinct, "
                    f"substantive objects. If those objects belong to other "
                    f"users this is an IDOR. Confirm with a second account."
                ),
                evidence=(
                    f"{param}={value} and {distinct_hits} neighbouring id(s) each "
                    f"returned HTTP 200 with distinct object content."
                ),
                poc=(
                    "(not validated — supply two accounts via --identity to let "
                    "Talon prove cross-user access, or confirm manually that the "
                    "neighbouring objects belong to a different user.)"
                ),
                remediation=(
                    "Enforce per-object authorization; consider unguessable "
                    "identifiers (UUIDs) as defence in depth."
                ),
                exchanges=[e for e in self.client.log[-3:]],
            )
        return None


def _normalize(body: str, id_value: str) -> str:
    """Strip the id itself and volatile tokens so similarity reflects structure."""
    text = body.replace(id_value, "§ID§")
    text = re.sub(r"\b\d{10,}\b", "§N§", text)              # timestamps/nonces
    text = re.sub(r'csrf[^"\'>]*["\']([^"\']+)', "csrf§", text, flags=re.I)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _ratio(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a, b).ratio()


def _curl(url: str, headers: dict[str, str]) -> str:
    hs = " ".join(f"-H {f'{k}: {v}'!r}" for k, v in headers.items())
    return f"curl -sS -i {hs} {url!r}"
