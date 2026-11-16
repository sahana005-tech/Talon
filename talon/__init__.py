"""Talon — a single-agent web vulnerability scanner that validates every
finding with a reproducible proof-of-concept before reporting it.

Design principle (borrowed from Strix): no PoC, no finding. A result only
graduates to the main report if Talon could prove it with a real request.

Talon is for AUTHORIZED security testing only — targets you own or that are
explicitly in scope for a bug-bounty / disclosure program. See talon/scope.py.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
