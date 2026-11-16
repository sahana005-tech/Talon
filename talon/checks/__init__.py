"""Vulnerability check modules.

Each check is a self-contained class that knows how to probe a surface,
detect a candidate issue, and VALIDATE it with a concrete request that
produces a reproducible proof-of-concept.

To add a class (e.g. SQLi, SSRF), subclass Check in base.py and register it in
ALL_CHECKS below. The agent and CLI pick these up automatically.
"""
from __future__ import annotations

from .base import Check, Finding
from .idor import IdorCheck
from .open_redirect import OpenRedirectCheck
from .reflected_xss import ReflectedXssCheck

ALL_CHECKS: dict[str, type[Check]] = {
    ReflectedXssCheck.id: ReflectedXssCheck,
    OpenRedirectCheck.id: OpenRedirectCheck,
    IdorCheck.id: IdorCheck,
}

__all__ = ["Check", "Finding", "ALL_CHECKS"]
