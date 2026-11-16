# Talon Security Assessment

- **Targets:** http://127.0.0.1:8000
- **In-scope hosts:** 127.0.0.1
- **Generated:** 2026-11-16 14:08:50 UTC
- **Surfaces tested:** 4 | **Requests:** 11 | **Duration:** 0.0s
- **LLM brain:** no (deterministic)

> **Authorized testing only.** This report documents issues Talon could reproduce against the scoped targets. Every *validated* finding below includes a proof-of-concept request. CVSS vectors are base scores and a starting point for the analyst to refine.

## Findings at a glance

| # | Severity | CVSS | Type | Location | Confidence |
|---|----------|------|------|----------|------------|
| 1 | 🟨 Medium | 6.5 | Insecure Direct Object Reference (BOLA) | http://127.0.0.1:8000/profile (`id`) | validated |
| 2 | 🟨 Medium | 6.1 | Reflected Cross-Site Scripting | http://127.0.0.1:8000/search (`q`) | validated |
| 3 | 🟨 Medium | 4.7 | Open Redirect | http://127.0.0.1:8000/go (`url`) | validated |

## Validated findings (with proof-of-concept)

### 1. Insecure Direct Object Reference (BOLA) — 🟨 Medium (CVSS 6.5)

- **URL:** http://127.0.0.1:8000/profile
- **Parameter:** `id`
- **CWE:** CWE-639
- **CVSS 3.1:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` → 6.5 (Medium)

**Description.** Object referenced by 'id=1' is returned to identity 'bob' even though it belongs to 'alice'. The endpoint enforces no object-level authorization, so any authenticated user can read other users' records by changing the identifier (IDOR/BOLA).

**Evidence.** 'alice' and 'bob' received byte-equivalent object-specific responses for id=1 (similarity 1.00), while a bogus id (7000004) returned HTTP 404 / distinct content — proving the response is object-specific, not a generic page.

**Proof of concept.**

```http
As user 'bob' (not the owner), request:
  GET http://127.0.0.1:8000/profile?id=1
  -> HTTP 200 containing 'alice'-owned data.

curl -sS -i -H 'Cookie: session=bob' 'http://127.0.0.1:8000/profile?id=1'
```

**Remediation.** Enforce an authorization check on every object access: verify the authenticated principal owns or may access the requested object before returning it. Do not rely on the identifier being unguessable.

<details><summary>Recorded response (excerpt)</summary>

```
HTTP 200
content-type: text/html; charset=utf-8

<!doctype html><html><body><h2>Alice Anand</h2><p>Email: alice@example.com</p><p>Private profile for user 1 — recovery code 11-AA-77.</p></body></html>
```
</details>

---

### 2. Reflected Cross-Site Scripting — 🟨 Medium (CVSS 6.1)

- **URL:** http://127.0.0.1:8000/search
- **Parameter:** `q`
- **CWE:** CWE-79
- **CVSS 3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` → 6.1 (Medium)

**Description.** The 'q' parameter is reflected into the HTML response without output encoding, allowing arbitrary HTML/JavaScript injection that executes in the victim's browser (reflected XSS).

**Evidence.** Parameter 'q' reflected the injected markup 't5d02232f"'><x>' into the HTML response body without entity-encoding (the characters < > " ' survived intact). Reflection context excerpt: ...ults for: t5d02232f"'><x></h2><p>No results.</p></body></html>...

**Proof of concept.**

```http
GET http://127.0.0.1:8000/search?q=%22%3E%3Csvg+onload%3Dalert%28document.domain%29%3E

Open the URL above in a browser; the injected <svg onload> fires in the page's origin. Reproduce with:
curl -sS -i 'http://127.0.0.1:8000/search?q=%22%3E%3Csvg+onload%3Dalert%28document.domain%29%3E'
```

**Remediation.** Contextually output-encode the parameter when writing it into HTML (HTML-entity encode <, >, ", ', &). Prefer the framework's auto-escaping templating. Add a restrictive Content-Security-Policy as defence in depth.

<details><summary>Recorded response (excerpt)</summary>

```
HTTP 200
content-type: text/html; charset=utf-8

<!doctype html><html><body><h2>Results for: t5d02232f"'><x></h2><p>No results.</p></body></html>
```
</details>

---

### 3. Open Redirect — 🟨 Medium (CVSS 4.7)

- **URL:** http://127.0.0.1:8000/go
- **Parameter:** `url`
- **CWE:** CWE-601
- **CVSS 3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N` → 4.7 (Medium)

**Description.** The 'url' parameter controls the redirect destination without validating it against an allow-list. An attacker can send victims a trusted-looking link that silently forwards them to an arbitrary external site (phishing, OAuth token theft).

**Evidence.** Request to http://127.0.0.1:8000/go?url=https%3A%2F%2Ftalon-oredir.example.com%2Fpoc returned HTTP 302 with Location: https://talon-oredir.example.com/poc — the server redirected to the attacker-controlled host 'talon-oredir.example.com'.

**Proof of concept.**

```http
GET http://127.0.0.1:8000/go?url=https%3A%2F%2Ftalon-oredir.example.com%2Fpoc
-> HTTP 302, Location: https://talon-oredir.example.com/poc

curl -sS -i 'http://127.0.0.1:8000/go?url=https%3A%2F%2Ftalon-oredir.example.com%2Fpoc'   # note: no -L, so the 3xx Location is visible
```

**Remediation.** Do not place user input directly in the redirect target. Validate against a server-side allow-list of permitted paths/hosts, or map an opaque key to the destination. If external redirects are required, show an interstitial.

<details><summary>Recorded response (excerpt)</summary>

```
HTTP 302
location: https://talon-oredir.example.com/poc


```
</details>

---

## Agent trace

```
PLAN: 1 target(s); checks=['reflected-xss', 'open-redirect', 'idor']; identities=['alice', 'bob']
MAP: crawling in-scope attack surface...
MAP: 4 surface(s) discovered; 3 parameter(s).
TEST: [VALIDATED] Reflected Cross-Site Scripting @ http://127.0.0.1:8000/search param=q (CVSS 6.1)
TEST: [VALIDATED] Open Redirect @ http://127.0.0.1:8000/go param=url (CVSS 4.7)
TEST: [VALIDATED] Insecure Direct Object Reference (BOLA) @ http://127.0.0.1:8000/profile param=id (CVSS 6.5)
GATE: 3 validated (with PoC), 0 probable; 11 requests.
```

---
_Generated by Talon v0.1 — validation-first web vulnerability agent._