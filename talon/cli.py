"""Talon command-line interface.

Examples
--------
    # Authorized scan of your own app, all three checks
    python -m talon --target https://your-app.com --authorize

    # Prove IDOR with two accounts, and draft a disclosure email
    python -m talon --target https://your-app.com --authorize \\
        --identity alice "Cookie: session=AAA" \\
        --identity bob   "Cookie: session=BBB" \\
        --disclose --researcher "Sahana H B"

    # Local test target
    python -m talon --target http://127.0.0.1:8000 --authorize --allow-local
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from urllib.parse import urlparse

from .agent import Agent
from .checks import ALL_CHECKS
from .llm import LLM
from .report import disclosure as disclosure_mod
from .report.report import to_json, to_markdown
from .scope import Scope, ScopeError
from .web import WebClient


def _parse_identity(items: list[list[str]]) -> list[dict]:
    identities = []
    for pair in items or []:
        label, header = pair[0], pair[1]
        name, _, value = header.partition(":")
        identities.append({"label": label, "headers": {name.strip(): value.strip()}})
    return identities


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="talon",
        description="Validation-first web vulnerability agent "
                    "(reflected XSS, open redirect, IDOR). AUTHORIZED USE ONLY.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--target", "-t", action="append", default=[], metavar="URL",
                   help="Target URL (repeatable).")
    p.add_argument("targets", nargs="*", help="Target URL(s) (positional).")
    p.add_argument("--authorize", action="store_true",
                   help="REQUIRED. Assert you own these targets or they are in "
                        "scope for a disclosure/bug-bounty program.")
    p.add_argument("--allow-local", action="store_true",
                   help="Permit scanning localhost/private IPs (your own test env).")
    p.add_argument("--checks", default="",
                   help=f"Comma list; default all. Available: {','.join(ALL_CHECKS)}")
    p.add_argument("--identity", action="append", nargs=2, default=[],
                   metavar=("LABEL", "HEADER"),
                   help="Auth identity for IDOR, e.g. --identity alice 'Cookie: s=..'. "
                        "Provide two to let Talon prove cross-user access.")
    p.add_argument("--max-pages", type=int, default=25, help="Crawl page budget.")
    p.add_argument("--rate", type=float, default=0.5, help="Seconds between requests.")
    p.add_argument("--max-requests", type=int, default=500, help="Hard request cap.")
    p.add_argument("--disclose", action="store_true",
                   help="Also draft a responsible-disclosure email per host.")
    p.add_argument("--program-policy", default=None,
                   help="Disclosure/bounty policy URL to cite in the email.")
    p.add_argument("--researcher", default="a security researcher",
                   help="Your name/handle for the disclosure email.")
    p.add_argument("--out", default=None, help="Output directory.")
    p.add_argument("--render", action="store_true",
                   help="Render pages in a headless browser so JavaScript runs "
                        "before crawling (needed for React/Vue/Angular/SPA sites). "
                        "Requires: pip install playwright && playwright install chromium.")
    p.add_argument("--render-wait", type=int, default=1500, metavar="MS",
                   help="Milliseconds to let each page settle after load (render mode).")
    p.add_argument("--quiet", action="store_true", help="Suppress live agent trace.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    targets = list(dict.fromkeys(args.target + args.targets))
    if not targets:
        print("error: no target given. Use --target URL.", file=sys.stderr)
        return 2

    try:
        scope = Scope.from_targets(targets, authorized=args.authorize,
                                   allow_local=args.allow_local)
        scope.require_authorized()
        scope.check_targets(targets)
    except ScopeError as e:
        print(f"\n  ⛔ {e}\n", file=sys.stderr)
        return 3

    check_ids = [c.strip() for c in args.checks.split(",") if c.strip()] or list(ALL_CHECKS)
    unknown = [c for c in check_ids if c not in ALL_CHECKS]
    if unknown:
        print(f"error: unknown check(s): {unknown}. Available: {list(ALL_CHECKS)}",
              file=sys.stderr)
        return 2

    identities = _parse_identity(args.identity)
    llm = LLM()

    if args.render:
        from .browser import available as _render_available
        if not _render_available():
            print("\n  ⛔ --render needs Playwright, which is not installed. Set it up:\n"
                  "       pip install playwright\n"
                  "       python3 -m playwright install chromium\n"
                  "     Or run without --render (stdlib crawler, raw HTML only).\n",
                  file=sys.stderr)
            return 4

    print("  ┌─ Talon v0.1 ─ validation-first web vuln agent")
    print(f"  │  {scope.banner()}")
    print(f"  │  checks: {', '.join(check_ids)}")
    print(f"  │  llm:    {llm.provider + '/' + llm.model if llm.enabled else 'off (deterministic)'}")
    print(f"  │  crawl:  {'rendered (headless Chromium)' if args.render else 'raw HTML (stdlib)'}")
    print("  └─ starting\n")

    logger = (lambda m: None) if args.quiet else (lambda m: print(f"    · {m}"))
    agent = Agent(
        scope, checks=check_ids, identities=identities,
        max_pages=args.max_pages, rate=args.rate, max_requests=args.max_requests,
        llm=llm, render=args.render, render_wait=args.render_wait, logger=logger,
    )
    result = agent.scan(targets)

    # Output dir
    out_dir = args.out or os.path.join("talon_runs", time.strftime("%Y%m%d-%H%M%S"))
    os.makedirs(out_dir, exist_ok=True)
    md_path = os.path.join(out_dir, "report.md")
    json_path = os.path.join(out_dir, "report.json")
    with open(md_path, "w") as fh:
        fh.write(to_markdown(result))
    with open(json_path, "w") as fh:
        fh.write(to_json(result))

    print(f"\n  ══ Results ═══════════════════════════════════════════")
    print(f"     validated (with PoC): {len(result.validated)}")
    print(f"     probable (review):    {len(result.probable)}")
    if result.budget_exhausted:
        print("     ⚠️  PARTIAL: request budget exhausted; raise --max-requests")
    for f in result.validated:
        print(f"       • {f.severity:8} CVSS {f.cvss_score:<4} {f.name} @ {f.url} "
              f"[{f.parameter}]")
    print(f"\n     report:  {md_path}")
    print(f"     json:    {json_path}")

    # Disclosure drafts
    if args.disclose:
        disc_client = WebClient(scope, rate=args.rate, max_requests=50)
        hosts = sorted(scope.allowed_hosts)
        for host in hosts:
            host_findings = [f for f in result.validated
                             if urlparse(f.url).hostname == host]
            if not host_findings:
                continue
            sec = None
            # Look on the origins actually targeted (scheme + port), not just
            # the bare hostname on 443/80.
            parsed = [urlparse(t if "://" in t else f"https://{t}") for t in targets]
            origins = list(dict.fromkeys(
                f"{p.scheme}://{p.netloc.rsplit('@', 1)[-1]}" for p in parsed
                if (p.hostname or "").lower() == host))
            try:
                sec = disclosure_mod.find_security_txt(disc_client, host, origins)
            except Exception:
                pass
            # Build a per-host view of the result for the drafter.
            from .agent import ScanResult
            host_result = ScanResult(
                targets=[t for t in targets if urlparse(
                    t if "://" in t else f"https://{t}").hostname == host] or targets,
                scope=scope, validated=host_findings,
            )
            email = disclosure_mod.draft_email(
                host_result, security_txt=sec, host=host,
                program_policy=args.program_policy, researcher=args.researcher,
            )
            disc_path = os.path.join(out_dir, f"disclosure_{host}.txt")
            with open(disc_path, "w") as fh:
                fh.write(email)
            src = sec.get("_source") if sec else "no security.txt"
            print(f"     disclosure ({host}): {disc_path}  [contact via {src}]")

    print("  ══════════════════════════════════════════════════════\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
