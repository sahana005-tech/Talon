"""Responsible-disclosure helper.

Two jobs:
  1. Locate a security contact per RFC 9116 (security.txt), checking
     /.well-known/security.txt then /security.txt.
  2. Draft a responsible-disclosure email from the validated findings — a
     courteous first-contact message that summarises impact and OFFERS full
     PoCs, rather than dumping exploit details on first contact.

This is the "tell them / email them" step, done the way that keeps a
researcher welcome in a program: through the published channel, with a clear
report, never as an unsolicited "we found bugs, pay us" blast.
"""
from __future__ import annotations

import re

from ..agent import ScanResult
from ..scope import Scope
from ..web import WebClient


def find_security_txt(client: WebClient, host: str,
                      origins: list[str] | None = None) -> dict | None:
    """Return parsed security.txt fields, or None if not found.

    `origins` are the scheme://host[:port] origins that were actually targeted;
    when given, only those are queried (so a target on :8443 is looked up on
    :8443, and no port the operator did not name is touched). Without them we
    fall back to the host's default https/http ports.
    """
    bases = origins or [f"https://{host}", f"http://{host}"]
    for base in bases:
        for path in ("/.well-known/security.txt", "/security.txt"):
            url = f"{base.rstrip('/')}{path}"
            try:
                resp = client.request(url)
            except Exception:
                continue
            if resp.status == 200 and resp.body and ":" in resp.body:
                fields = _parse_security_txt(resp.body)
                if fields.get("contact"):
                    fields["_source"] = url
                    return fields
    return None


def _parse_security_txt(text: str) -> dict:
    fields: dict[str, list[str] | str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip().lower()
        val = val.strip()
        if key == "contact":
            fields.setdefault("contact", [])
            fields["contact"].append(val)  # type: ignore[union-attr]
        else:
            fields[key] = val
    return fields


def _primary_email(fields: dict | None, host: str) -> str:
    if fields:
        for c in fields.get("contact", []):
            if c.lower().startswith("mailto:"):
                return c[len("mailto:"):]
            if "@" in c and "://" not in c:
                return c
    return f"security@{host}  (NO security.txt found — verify this address)"


def draft_email(result: ScanResult, *, security_txt: dict | None, host: str,
                program_policy: str | None = None, researcher: str = "a security researcher") -> str:
    to = _primary_email(security_txt, host)
    validated = result.validated
    n = len(validated)
    sev_counts: dict[str, int] = {}
    for f in validated:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    sev_line = ", ".join(f"{v}×{k}" for k, v in sev_counts.items()) or "—"

    bullet_lines = "\n".join(
        f"  {i}. {f.name} ({f.severity}, CVSS {f.cvss_score}) — {f.url}"
        + (f" [param: {f.parameter}]" if f.parameter else "")
        for i, f in enumerate(validated, 1)
    )

    policy_line = (
        f"I'm submitting this under your disclosure policy ({program_policy})."
        if program_policy else
        "Please let me know your preferred process for handling this report."
    )

    lines = [
        f"To: {to}",
        f"Subject: Security disclosure: {n} validated vulnerabilit"
        f"{'y' if n == 1 else 'ies'} in {host} ({sev_line})",
        "",
        "Hello,",
        "",
        f"I'm {researcher} and I'd like to responsibly disclose "
        f"{n} security issue{'' if n == 1 else 's'} I identified and verified "
        f"on {host}. {policy_line}",
        "",
        "Summary of validated findings (each reproduced with a proof-of-concept):",
        bullet_lines or "  (none)",
        "",
        "I have working, non-destructive proof-of-concept requests and a full "
        "technical report (impact, reproduction steps, CVSS, remediation) ready "
        "to share through whatever secure channel you prefer. I have not "
        "accessed or retained any data beyond what was necessary to confirm each "
        "issue, and I have not disclosed this to anyone else.",
        "",
        "I'm happy to assist with verification and retesting after a fix. I'll "
        "follow coordinated disclosure and won't publish any details without "
        "your go-ahead.",
        "",
        "Thank you for your time and for running a channel for reports like this.",
        "",
        "Best regards,",
        researcher,
    ]
    header_note = []
    if security_txt:
        header_note.append(f"[contact resolved from {security_txt.get('_source')}]")
        if security_txt.get("policy"):
            header_note.append(f"[policy: {security_txt['policy']}]")
    else:
        header_note.append("[no security.txt found — confirm the contact before sending]")
    return "\n".join(header_note) + "\n\n" + "\n".join(lines)
