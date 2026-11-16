# 🦉 Talon

**A single-agent, validation-first web vulnerability scanner.**
Give it a site; it finds issues, **proves each one with a reproducible
proof-of-concept**, scores it with CVSS 3.1, and drafts a responsible-disclosure
email. Inspired by [Strix](https://github.com/usestrix/strix)'s "no PoC, no
finding" philosophy — scoped down to three classes done rigorously.

> ⚠️ **Authorized use only.** Talon is for targets you own or that are
> explicitly in scope for a bug-bounty / vulnerability-disclosure program.
> It refuses to run without `--authorize` and never leaves the hosts you name.
> Unauthorized scanning is illegal in most jurisdictions and gets researchers
> banned from programs. Don't.

---

## Why it exists

Classic scanners drown you in "potential" findings you still have to verify by
hand. Talon flips that: **a result only reaches the main report if Talon could
reproduce it with a single request.** Everything else is parked under
"probable" for manual review, with no PoC claimed. That means the report you
hand to a program is one you can stand behind.

## Zero dependencies

Pure Python standard library (3.9+). Nothing to `pip install`.

```bash
git clone https://github.com/sahana005-tech/Talon.git && cd Talon
python3 -m talon --help
```

## The three checks

| Check | CWE | How it's validated | Default CVSS |
|-------|-----|--------------------|--------------|
| **Reflected XSS** | CWE-79 | Injects a canary with `< > " '`, works out the context (HTML text, attribute, script string), then confirms a matching breakout payload reflects **verbatim** | 6.1 Medium |
| **Open Redirect** | CWE-601 | Injects an external canary host; confirms a **3xx `Location`** points to it | 4.7 Medium |
| **IDOR / BOLA** | CWE-639 | Two accounts: proves account **B** can read account **A**'s object, that the endpoint distinguishes valid vs bogus IDs, and that the object is **not public** (unauthenticated control request) | 6.5 Medium |

CVSS vectors are **base scores** — a starting point you refine per finding.

## Quick start

```bash
# 1) See it work against the bundled vulnerable app
python3 demo/vuln_app.py &                     # serves on 127.0.0.1:8000
python3 -m talon --target http://127.0.0.1:8000 --authorize --allow-local \
    --identity alice "Cookie: session=alice" \
    --identity bob   "Cookie: session=bob" \
    --disclose --researcher "Your Name"

# 2) A real authorized target
python3 -m talon --target https://your-app.com --authorize \
    --identity alice "Cookie: session=AAA" \
    --identity bob   "Cookie: session=BBB" \
    --disclose --program-policy https://your-app.com/.well-known/security.txt
```

### Proving IDOR
IDOR is about *authorization*, so it needs identities. Pass **two** accounts
with `--identity LABEL "Header: value"`. Talon then proves cross-user access
instead of guessing. With one or zero identities it only reports *probable*
enumeration (no PoC claimed) — honest by design.

## Output

Each run writes to `talon_runs/<timestamp>/` (or `--out DIR`):

- `report.md` — human report: summary table, per-finding description, evidence,
  **copy-pasteable PoC**, remediation, recorded response, and the agent's
  reasoning trace.
- `report.json` — machine-readable findings for pipelines.
- `disclosure_<host>.txt` — a courteous first-contact email built from the
  validated findings, addressed to the contact in the host's
  [`security.txt`](https://www.rfc-editor.org/rfc/rfc9116) when present. It
  summarises impact and *offers* full PoCs rather than dumping exploits on
  first contact — the way that keeps you welcome in a program.

## Report viewer

`viewer.html` is a single self-contained page (no dependencies, no network)
that turns a `report.json` into an interactive view:

```bash
open viewer.html        # then drop in talon_runs/<run>/report.json
```

- Summary tiles, findings sorted by severity, and a filter for validated vs
  probable.
- Click a finding to expand its description, evidence, copyable PoC and
  remediation.
- The agent trace replays line by line while the `PLAN → MAP → TEST → GATE`
  rail lights up.
- Light and dark themes; severity is the only colour.

The viewer is read-only on purpose: scans only ever start from the CLI, behind
`--authorize`. Report text is rendered as plain text, never as HTML, because
reports contain attack strings.

## The agent

One orchestrating agent runs a `PLAN → MAP → TEST → GATE` loop:

- **PLAN** — seeds + (optional) LLM-suggested parameter names.
- **MAP** — same-origin crawl building an attack-surface inventory (links,
  query params, GET and POST form fields).
- **TEST** — every enabled check against every surface.
- **GATE** — dedupe; split *validated* (has PoC) from *probable*.

### Optional LLM brain (bring your own key)
Talon is fully deterministic without an LLM. If you set one, it *only*
(a) suggests extra parameter names to probe — which still go through the same
validation gate, and (b) writes the executive summary. **The LLM can never
invent a finding.**

```bash
export TALON_LLM="anthropic/claude-sonnet-4-5"   # native Anthropic
export LLM_API_KEY="sk-..."

# or native OpenAI:
export TALON_LLM="openai/gpt-4o-mini"

# or ANY OpenAI-compatible endpoint (local Ollama, a hosted provider's
# compatibility endpoint, etc.) — give the provider's model id and /v1 base:
export TALON_LLM="openai-compat/<model-id>"
export LLM_BASE_URL="https://<provider-host>/v1"
export LLM_API_KEY="..."                         # any placeholder for local
```

Model strength barely matters: the LLM only suggests extra parameter names
(still run through the validation gate) and writes the summary. A small/cheap
or local model is plenty.

## Safety controls

- `--authorize` is mandatory; no flag, no scan.
- Stays strictly on the exact origins (scheme + host + **port**) you name; a
  different port on the same host, and any off-origin link/redirect, is
  catalogued but never probed.
- Cloud metadata / link-local hosts are always blocked — including hostnames
  that *resolve* to them.
- `--allow-local` is required to touch localhost/private IPs; this is enforced
  by resolving the hostname, so a public name pointing at a private address is
  still blocked.
- Rate-limited (`--rate`) and hard request cap (`--max-requests`).
- All payloads are non-destructive (inert markup). POST forms are only
  probed for reflected XSS; redirect and IDOR checks never submit them.

## Extending it (add a 4th class)

1. Subclass `Check` in `talon/checks/` and implement `run(surface)`.
2. Return `Finding(...)` objects; set `confidence="validated"` only when you
   have a reproducing request.
3. Register it in `talon/checks/__init__.py::ALL_CHECKS`.

The agent and CLI pick it up automatically.

## Tests

```bash
python3 -m unittest tests.test_core -v
```

## Roadmap / ideas

- SQLi (boolean/error differential) and SSRF (callback-based) checks.
- **Source-aware mode for Dolibarr**: feed a known access-control bug, let
  Semgrep + triage generalise it into variants — pairs with this runtime engine.
- Authenticated crawling (login flow).
- Submission adapters (HackerOne / Bugcrowd / email) behind the disclosure draft.

## License

MIT (see `LICENSE`). Use responsibly.
