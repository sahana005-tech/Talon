"""Optional LLM brain for the agent (bring-your-own-key, stdlib only).

Talon works fully without an LLM — the checks are deterministic and do the
validation. The LLM, when configured, only ever does two *advisory* things:

  1. Suggests additional parameter / endpoint names to probe (candidates are
     then tested by the same deterministic, validation-first checks — the LLM
     can never create a finding on its own).
  2. Writes human-readable prose for the report's executive summary.

Configure via environment:
    TALON_LLM=anthropic/claude-sonnet-4-5    (native Anthropic Messages API)
    TALON_LLM=openai/gpt-4o-mini             (native OpenAI Chat Completions)
    LLM_API_KEY=sk-...

Any OpenAI-compatible endpoint (many providers expose one) works via the
`openai-compat` provider plus a base URL — for example a local Ollama server
or a hosted provider's compatibility endpoint:

    TALON_LLM=openai-compat/<model-id>
    LLM_BASE_URL=https://<provider-host>/v1      # the /v1 base, no trailing path
    LLM_API_KEY=...                              # or any placeholder for local

Model strength barely matters here: the LLM only suggests extra parameter names
(still validated by the deterministic checks) and writes the summary prose.
"""
from __future__ import annotations

import json
import os
import urllib.request

# Providers that speak the OpenAI Chat Completions schema.
_OPENAI_COMPATIBLE = {"openai", "openai-compat", "compat"}


class LLM:
    def __init__(
        self,
        spec: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
    ):
        spec = spec or os.environ.get("TALON_LLM", "")
        self.api_key = api_key or os.environ.get("LLM_API_KEY", "")
        self.provider, _, self.model = spec.partition("/")
        self.base_url = (base_url or os.environ.get("LLM_BASE_URL", "")).rstrip("/")
        self.enabled = bool(self.provider and self.model and self.api_key)

    def complete(self, system: str, user: str, *, max_tokens: int = 1024) -> str | None:
        if not self.enabled:
            return None
        try:
            if self.provider == "anthropic":
                return self._anthropic(system, user, max_tokens)
            if self.provider in _OPENAI_COMPATIBLE:
                return self._openai(system, user, max_tokens)
        except Exception:
            return None  # advisory only — never break a scan on LLM failure
        return None

    def _post(self, url: str, headers: dict, payload: dict) -> dict:
        data = json.dumps(payload).encode()
        # Some providers' edges reject Python's default "Python-urllib" agent.
        headers = {"user-agent": "Talon/0.1", **headers}
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode())

    def _anthropic(self, system, user, max_tokens) -> str:
        out = self._post(
            "https://api.anthropic.com/v1/messages",
            {
                "content-type": "application/json",
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
            },
            {
                "model": self.model,
                "max_tokens": max_tokens,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            },
        )
        return "".join(b.get("text", "") for b in out.get("content", []))

    def _openai(self, system, user, max_tokens) -> str | None:
        # Default to OpenAI's host for the plain "openai" provider; any other
        # OpenAI-compatible endpoint must supply LLM_BASE_URL.
        base = self.base_url or (
            "https://api.openai.com/v1" if self.provider == "openai" else ""
        )
        if not base:
            return None  # openai-compat without a base URL: nothing to call
        out = self._post(
            f"{base}/chat/completions",
            {"content-type": "application/json", "authorization": f"Bearer {self.api_key}"},
            {
                "model": self.model,
                "max_tokens": max_tokens,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
        )
        return out["choices"][0]["message"]["content"]

    def suggest_params(self, url: str, known: list[str]) -> list[str]:
        """Ask the LLM for likely injectable param names on an endpoint."""
        system = (
            "You are a web security testing assistant. Given a URL, suggest "
            "likely query-parameter names an endpoint might accept that are "
            "worth testing for reflected XSS, open redirect, or IDOR. Reply "
            "ONLY with a JSON array of lowercase parameter-name strings."
        )
        raw = self.complete(system, f"URL: {url}\nAlready known params: {known}")
        if not raw:
            return []
        try:
            start, end = raw.find("["), raw.rfind("]")
            arr = json.loads(raw[start : end + 1])
            return [str(x) for x in arr if isinstance(x, (str,))][:12]
        except Exception:
            return []
