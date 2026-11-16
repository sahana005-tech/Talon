"""CVSS v3.1 base-score calculator (self-contained, spec-accurate).

Reference: FIRST CVSS v3.1 specification, section 7.1 (Base Metrics).
We implement the base score only — that is what a single validated finding
warrants. Temporal/environmental metrics are left for the analyst to add.

A vector looks like:  AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
"""
from __future__ import annotations

import math
from dataclasses import dataclass

# Metric weight tables (CVSS v3.1 spec, section 7.4)
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.00, "L": 0.22, "H": 0.56}
# Privileges Required depends on Scope
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}

_METRIC_ORDER = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]


@dataclass
class CvssResult:
    vector: str
    base_score: float
    severity: str


def _roundup(value: float) -> float:
    """CVSS v3.1 Appendix A roundup: round up to one decimal place."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def severity_rating(score: float) -> str:
    """CVSS v3.1 qualitative severity bands."""
    if score == 0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def parse_vector(vector: str) -> dict[str, str]:
    """Parse the metric portion of a CVSS vector string.

    Accepts an optional 'CVSS:3.1/' prefix. Returns the 8 base metrics.
    """
    metrics: dict[str, str] = {}
    for part in vector.strip().split("/"):
        if not part or ":" not in part:
            continue
        key, _, val = part.partition(":")
        key = key.strip().upper()
        if key == "CVSS":
            continue
        metrics[key] = val.strip().upper()
    missing = [m for m in _METRIC_ORDER if m not in metrics]
    if missing:
        raise ValueError(f"CVSS vector missing base metrics: {', '.join(missing)}")
    return metrics


def score(vector: str) -> CvssResult:
    """Compute the CVSS v3.1 base score for a vector string."""
    m = parse_vector(vector)
    scope_changed = m["S"] == "C"

    # Impact Sub-Score (ISS)
    iss = 1 - (
        (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
    )

    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED
    exploitability = (
        8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr_table[m["PR"]] * _UI[m["UI"]]
    )

    if impact <= 0:
        base = 0.0
    elif scope_changed:
        base = _roundup(min(1.08 * (impact + exploitability), 10.0))
    else:
        base = _roundup(min(impact + exploitability, 10.0))

    canonical = "CVSS:3.1/" + "/".join(f"{k}:{m[k]}" for k in _METRIC_ORDER)
    return CvssResult(vector=canonical, base_score=base, severity=severity_rating(base))


if __name__ == "__main__":
    # Spot-checks against FIRST's published examples.
    for vec, expected in [
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),   # unauth RCE
        ("AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),   # reflected XSS
        ("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),   # IDOR read
        ("AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N", 4.7),   # open redirect
    ]:
        r = score(vec)
        status = "ok" if abs(r.base_score - expected) < 0.05 else "MISMATCH"
        print(f"{status:9} {r.base_score:>4}  (expected {expected})  {r.severity:8} {vec}")
