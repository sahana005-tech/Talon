"""Shared types for all checks."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..report.cvss import score as cvss_score

if TYPE_CHECKING:
    from ..crawler import Surface
    from ..web import WebClient


@dataclass
class Finding:
    """A single result. `confidence` governs whether it reaches the main report.

    confidence == "validated"  -> Talon proved it with a request (has a PoC).
    confidence == "probable"   -> strong signal but not fully proven; appendix.
    """
    check_id: str
    name: str
    url: str
    cvss_vector: str
    description: str
    evidence: str
    poc: str
    remediation: str
    parameter: str | None = None
    confidence: str = "validated"
    cwe: str | None = None
    exchanges: list = field(default_factory=list)  # list[Exchange] for the report

    # Filled in by __post_init__ from the vector.
    cvss_score: float = 0.0
    severity: str = "None"

    def __post_init__(self) -> None:
        result = cvss_score(self.cvss_vector)
        self.cvss_vector = result.vector
        self.cvss_score = result.base_score
        self.severity = result.severity

    def key(self) -> tuple:
        """Dedup key: same class + url + parameter is one finding."""
        return (self.check_id, self.url.split("?")[0], self.parameter)


class Check:
    """Base class for a vulnerability check.

    Subclasses set `id`, `name`, `cwe`, and implement `run`.
    """
    id: str = ""
    name: str = ""
    cwe: str | None = None

    def __init__(self, client: "WebClient", context: dict | None = None):
        self.client = client
        # Shared run context (e.g. IDOR identities, LLM handle). Optional.
        self.context: dict = context or {}

    def run(self, surface: "Surface") -> list[Finding]:
        """Probe a single surface (URL + its params/forms). Return findings."""
        raise NotImplementedError
