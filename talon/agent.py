"""The orchestrating agent.

One agent, a reasoning loop, and a toolkit (crawler + checks + web client).
This mirrors Strix's shape — an agent that plans, acts with tools, observes,
and iterates — but scoped to three validatable vulnerability classes and with
a deterministic validation gate so findings are provable, not hallucinated.

Loop phases:
    PLAN  -> decide seeds and (optionally, via LLM) extra params to probe
    MAP   -> crawl in-scope to build the attack surface
    TEST  -> run each enabled check against every surface
    GATE  -> dedupe; split validated (has PoC) vs probable
    REPORT is handled by talon.report.report
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from .checks import ALL_CHECKS, Finding
from .crawler import Crawler, Surface
from .llm import LLM
from .scope import Scope
from .web import BudgetExceeded, WebClient


@dataclass
class ScanResult:
    targets: list[str]
    scope: Scope
    validated: list[Finding] = field(default_factory=list)
    probable: list[Finding] = field(default_factory=list)
    surfaces_tested: int = 0
    requests_made: int = 0
    reasoning: list[str] = field(default_factory=list)
    started: float = 0.0
    finished: float = 0.0
    llm_used: bool = False
    budget_exhausted: bool = False   # True -> scan stopped early; results partial
    rendered: int = 0                # pages rendered with a headless browser (render mode)
    surfaces: list = field(default_factory=list)  # inventory of what was tested


class Agent:
    def __init__(
        self,
        scope: Scope,
        *,
        checks: list[str] | None = None,
        identities: list[dict] | None = None,
        max_pages: int = 25,
        rate: float = 0.5,
        max_requests: int = 500,
        llm: LLM | None = None,
        render: bool = False,
        render_wait: int = 1500,
        logger=None,
    ):
        self.scope = scope
        self.check_ids = checks or list(ALL_CHECKS.keys())
        self.identities = identities or []
        self.max_pages = max_pages
        self.rate = rate
        self.max_requests = max_requests
        self.llm = llm or LLM()
        self.render = render            # render JS with a headless browser first
        self.render_wait = render_wait  # ms to let a page settle after load
        self._log = logger or (lambda m: None)
        self.reasoning: list[str] = []

    def _think(self, msg: str) -> None:
        self.reasoning.append(msg)
        self._log(msg)

    def scan(self, targets: list[str]) -> ScanResult:
        self.scope.require_authorized()
        self.scope.check_targets(targets)
        result = ScanResult(targets=targets, scope=self.scope, started=time.time())

        client = WebClient(
            self.scope, rate=self.rate, max_requests=self.max_requests
        )
        context = {"identities": self.identities, "llm": self.llm}

        # PLAN
        self._think(f"PLAN: {len(targets)} target(s); checks={self.check_ids}; "
                    f"identities={[i['label'] for i in self.identities] or 'none'}")
        if self.llm.enabled:
            result.llm_used = True
            self._think(f"PLAN: LLM brain active ({self.llm.provider}/{self.llm.model}) "
                        f"for param suggestion + summary.")

        # MAP
        if self.render:
            from .browser import BrowserCrawler, RenderError
            self._think("MAP: rendering pages in headless Chromium, then reading "
                        "the live DOM for links and forms...")
            crawler = BrowserCrawler(client, self.scope, max_pages=self.max_pages,
                                     rate=self.rate, settle_ms=self.render_wait)
            try:
                surfaces = crawler.crawl(targets)
                result.rendered = crawler.pages_rendered
                self._think(f"MAP: rendered {crawler.pages_rendered} page(s) with JS.")
            except RenderError as e:
                raise RenderError(str(e)) from None
        else:
            self._think("MAP: crawling in-scope attack surface (raw HTML)...")
            crawler = Crawler(client, self.scope, max_pages=self.max_pages)
            surfaces = crawler.crawl(targets)
        if crawler.budget_exhausted:
            result.budget_exhausted = True
            self._think(f"MAP: request budget ({self.max_requests}) exhausted while "
                        f"crawling; the surface map is incomplete.")
        surfaces = self._augment_with_llm(surfaces)
        self._think(f"MAP: {len(surfaces)} surface(s) discovered; "
                    f"{sum(len(s.params) for s in surfaces)} parameter(s).")
        result.surfaces = [
            {"method": s.method, "url": s.url.split("?")[0], "params": sorted(s.params)}
            for s in surfaces
        ]
        for s in result.surfaces:                       # make the surface visible
            ps = ", ".join(s["params"]) or "(no params)"
            self._think(f"MAP: surface  {s['method']:4} {s['url']}  [{ps}]")

        # TEST
        check_instances = [ALL_CHECKS[cid](client, context) for cid in self.check_ids]
        all_findings: list[Finding] = []
        stopped = False
        for surface in surfaces:
            for check in check_instances:
                try:
                    found = check.run(surface)
                except BudgetExceeded:
                    stopped = True
                    break
                except Exception as e:  # a broken check must not kill the scan
                    self._think(f"TEST: {check.id} errored on {surface.url}: {e}")
                    continue
                for f in found:
                    tag = "VALIDATED" if f.confidence == "validated" else "probable"
                    self._think(f"TEST: [{tag}] {f.name} @ {f.url} "
                                f"param={f.parameter} (CVSS {f.cvss_score})")
                all_findings.extend(found)
            if stopped:
                result.budget_exhausted = True
                self._think(f"TEST: request budget ({self.max_requests}) exhausted; "
                            f"stopping early with "
                            f"{len(surfaces) - result.surfaces_tested} surface(s) not "
                            f"fully tested. Raise --max-requests.")
                break
            result.surfaces_tested += 1

        # GATE
        deduped = _dedupe(all_findings)
        result.validated = [f for f in deduped if f.confidence == "validated"]
        result.probable = [f for f in deduped if f.confidence == "probable"]
        result.validated.sort(key=lambda f: f.cvss_score, reverse=True)
        result.probable.sort(key=lambda f: f.cvss_score, reverse=True)
        result.requests_made = client.count
        result.finished = time.time()
        self._think(f"GATE: {len(result.validated)} validated (with PoC), "
                    f"{len(result.probable)} probable; {client.count} requests."
                    + (" PARTIAL: request budget exhausted." if result.budget_exhausted else ""))
        self.reasoning = list(self.reasoning)
        result.reasoning = self.reasoning
        return result

    def _augment_with_llm(self, surfaces: list[Surface]) -> list[Surface]:
        if not self.llm.enabled:
            return surfaces
        for s in surfaces[:8]:  # cap LLM calls
            extra = self.llm.suggest_params(s.url, list(s.params.keys()))
            added = [p for p in extra if p not in s.params]
            for p in added:
                s.params.setdefault(p, "1")
            if added:
                self._think(f"PLAN(LLM): added candidate params on {s.url}: {added}")
        return surfaces


def _dedupe(findings: list[Finding]) -> list[Finding]:
    best: dict[tuple, Finding] = {}
    for f in findings:
        k = f.key()
        # Prefer validated over probable; otherwise keep higher score.
        if k not in best:
            best[k] = f
            continue
        cur = best[k]
        if (f.confidence == "validated") and (cur.confidence != "validated"):
            best[k] = f
        elif f.confidence == cur.confidence and f.cvss_score > cur.cvss_score:
            best[k] = f
    return list(best.values())
