"""Pluggable review backends. A backend takes prompt TEXT (system + user) and a JSON schema, asks a
model for a verdict, validates it client-side against the schema, and returns the raw JSON string. Any
availability failure (down / timeout / refused / malformed / schema-invalid) maps to ReviewUnavailable so
the orchestrator's heuristic fallback engages and a flagged release is never silently dropped.

Two adapters cover every provider PyDiffWatch targets:
  - OpenAICompatibleBackend: any OpenAI-compatible /v1 endpoint (OpenAI, Ollama, llama.cpp, llama-swap,
    vLLM, LM Studio, OpenRouter, ...). Optional bearer auth from a named env var; tiered structured output.
  - AnthropicBackend: the native Anthropic SDK (lazy-imported, key from host env).

CONTAINMENT: network egress targets ONLY the configured endpoint. Untrusted package content reaches a
backend solely as request-body TEXT — never as a URL the backend fetches. This module is the system's
single sanctioned egress; reviewer.py (which handles the diff text) stays network-free."""
import json
import logging
import urllib.request

from . import egress

logger = logging.getLogger(__name__)


class ReviewUnavailable(Exception):
    """Raised when the model is down/timed-out/rate-limited/malformed/schema-invalid after retries.
    The orchestrator falls back to a heuristic-only alert so a flagged release is never silently dropped."""


def _urllib_post_json(url: str, payload: dict, timeout: float, headers: dict | None = None) -> dict:
    """POST JSON to the configured endpoint and return the parsed JSON response. The single network
    egress in the codebase; `url` is always the backend's configured endpoint (never package data)."""
    egress.assert_web_scheme(url)
    body = json.dumps(payload).encode()
    # Explicit UA: the stdlib default "Python-urllib/3.x" is silently 403'd by some API gateways
    # (Cloudflare/WAF). Matches fetcher.py's egress identity. Caller-supplied headers still win.
    hdrs = {"Content-Type": "application/json", "User-Agent": "diffwatch/0.1", **(headers or {})}
    req = urllib.request.Request(url, data=body, headers=hdrs)
    # url is the operator-configured reviewer endpoint (scheme-guarded above), never package data.
    with urllib.request.urlopen(req, timeout=timeout) as r:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        return json.loads(r.read())


# Enum fields that must NOT hard-fail on an out-of-enum value: a loose/prompt-only endpoint may emit a
# synonym, and discarding the whole verdict over it would throw away the decision signal. These are
# clamped toward caution at Verdict construction (reviewer.py): attack_type -> "none", and
# recommended_action -> report-to-pypi (malicious) / monitor (otherwise). Only `classification` — for
# which no safe default exists — stays a hard failure. This check itself is non-mutating.
_SOFT_ENUM_KEYS = frozenset({"attack_type", "recommended_action"})


def validate_verdict(parsed, schema):
    """Minimal client-side schema check (no jsonschema dep): required keys present, enum membership.
    Raises ReviewUnavailable on any miss (except _SOFT_ENUM_KEYS, which are clamped downstream). Used
    in EVERY structured-output mode so a loose/prompt-only endpoint can never slip an out-of-contract
    verdict past the reviewer. Non-mutating: returns `parsed` unchanged."""
    if not isinstance(parsed, dict):
        raise ReviewUnavailable(f"verdict is not a JSON object (got {type(parsed).__name__}): the model "
                                f"returned malformed output; lower structured_output or use a stronger model.")
    for key in schema.get("required", []):
        if key not in parsed:
            raise ReviewUnavailable(f"verdict missing required key {key!r}: the model returned an incomplete "
                                    f"verdict, often truncated by a reasoning model. Raise "
                                    f"reviewer.max_output_tokens, or disable thinking via [reviewer.extra_body].")
    for key, spec in schema.get("properties", {}).items():
        if key in parsed and "enum" in spec and parsed[key] not in spec["enum"]:
            if key in _SOFT_ENUM_KEYS:
                continue
            raise ReviewUnavailable(f"verdict {key}={parsed[key]!r} is not one of {spec['enum']}: the model "
                                    f"returned an out-of-contract value. Lower structured_output "
                                    f"(json_schema -> json_object -> none) or use a more capable model.")
    return parsed


def _egress_hint(e) -> str:
    """Turn a transport failure into a ReviewUnavailable message that points at the likely fix, so the
    operator isn't left with a bare 'HTTP Error 400'. `urllib`'s HTTPError carries a numeric `.code`."""
    base = str(e) or type(e).__name__
    code = getattr(e, "code", None)
    if code == 400:
        return (f"reviewer endpoint returned HTTP 400 ({base}): the request was rejected — many endpoints "
                f"(e.g. DeepSeek) reject the strict json_schema response_format. Set "
                f'structured_output = "json_object" in [reviewer] (see examples/deepseek.toml).')
    if code in (401, 403):
        return (f"reviewer endpoint returned HTTP {code} ({base}): auth failed or the client was blocked. "
                f"Check api_key_env names an env var that is set in this process and the key is valid.")
    if code == 404:
        return (f"reviewer endpoint returned HTTP 404 ({base}): check base_url (it usually ends in /v1) and "
                f"that the model name exists on this endpoint.")
    if code == 429:
        return f"reviewer endpoint returned HTTP 429 ({base}): rate-limited. Back off or raise reviewer.timeout."
    if code is not None:
        return f"reviewer endpoint returned HTTP {code} ({base})."
    if isinstance(e, OSError):    # URLError / connection refused / timeout (HTTPError has a code, above)
        return (f"could not reach reviewer endpoint ({base}): check base_url host/port and the trailing /v1, "
                f"and that the model server is running.")
    return base


class OpenAICompatibleBackend:
    """OpenAI-compatible chat-completions backend. `base_url` is the /v1 root of any compatible server.
    structured_output: "json_schema" (strict, preferred) | "json_object" (loose JSON) | "none" (prompt-only).
    The verdict is always validated client-side against the schema regardless of mode."""

    def __init__(self, base_url, model, *, api_key_env=None, structured_output="json_schema",
                 escalation_model=None, post=None, timeout: float = 120.0, extra_body=None):
        self.endpoint = base_url.rstrip("/")
        self.primary_model = model
        self.escalation_model = escalation_model
        self.api_key_env = api_key_env
        self.structured_output = structured_output
        self._post = post if post is not None else _urllib_post_json
        self._timeout = timeout
        # Provider-specific knobs (e.g. DeepSeek reasoning toggle) merged verbatim; core fields override.
        self.extra_body = extra_body or {}

    def _auth_headers(self) -> dict:
        if not self.api_key_env:
            return {}
        import os
        key = os.environ.get(self.api_key_env)
        return {"Authorization": f"Bearer {key}"} if key else {}

    def complete(self, *, model, system, user_text, schema, max_tokens) -> str:
        # extra_body first so the reserved core fields below (and response_format) always win — a stray
        # operator key can never override the model, the injection-delimited messages, or the token cap.
        payload = {
            **self.extra_body,
            "model": model,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user_text}],
            "max_tokens": max_tokens,
            "temperature": 0.2,
        }
        if self.structured_output == "json_schema":
            payload["response_format"] = {"type": "json_schema",
                                          "json_schema": {"name": "review", "strict": True, "schema": schema}}
        elif self.structured_output == "json_object":
            payload["response_format"] = {"type": "json_object"}
        # "none": prompt-only; no response_format (the system prompt already demands JSON).
        try:
            data = self._post(f"{self.endpoint}/chat/completions", payload, self._timeout, self._auth_headers())
        except Exception as e:                    # connection/timeout/HTTP/JSON -> fallback (with a fix hint)
            raise ReviewUnavailable(_egress_hint(e)) from e
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as e:
            raise ReviewUnavailable(f"malformed response: {e}") from e
        if not isinstance(content, str):
            raise ReviewUnavailable(f"non-string content: {content!r}")
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError as e:
            raise ReviewUnavailable(f"model did not return JSON ({e}): lower structured_output "
                                    f"(json_schema -> json_object -> none) or raise "
                                    f"reviewer.max_output_tokens.") from e
        validate_verdict(parsed, schema)
        return content


class AnthropicBackend:
    """Anthropic SDK backend. Sonnet baseline with optional Opus escalation on low confidence."""

    def __init__(self, model, escalation_model=None, *, client=None):
        self.primary_model = model
        self.escalation_model = escalation_model
        if client is None:
            import anthropic                       # lazy: optional dep, only when this backend is used
            client = anthropic.Anthropic()         # reads ANTHROPIC_API_KEY from host env
        self.client = client

    def complete(self, *, model, system, user_text, schema, max_tokens) -> str:
        import anthropic
        try:
            resp = self.client.messages.create(
                model=model,
                max_tokens=max_tokens,
                thinking={"type": "adaptive"},
                system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
                output_config={"format": {"type": "json_schema", "schema": schema}},
                messages=[{"role": "user", "content": user_text}],
            )
        except anthropic.APIError as e:            # 4xx/5xx/timeout/connection after SDK retries
            raise ReviewUnavailable(str(e)) from e
        text = next((b.text for b in resp.content if getattr(b, "type", None) == "text"), None)
        if text is None:
            raise ReviewUnavailable("no text block in response")
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as e:
            raise ReviewUnavailable(f"non-JSON content: {e}") from e
        validate_verdict(parsed, schema)
        return text


def make_backend(cfg, client=None):
    """Construct the configured review backend from cfg.reviewer. Neither path opens a connection at
    construction. `client` injects an Anthropic client for tests (avoids SDK import / API key)."""
    rc = cfg.reviewer
    if rc.provider == "openai":
        return OpenAICompatibleBackend(rc.base_url, rc.model, api_key_env=rc.api_key_env,
                                       structured_output=rc.structured_output,
                                       escalation_model=rc.escalation_model, timeout=rc.timeout,
                                       extra_body=rc.extra_body)
    if rc.provider == "anthropic":
        return AnthropicBackend(rc.model, rc.escalation_model, client=client)
    raise ValueError(f"unknown reviewer provider: {rc.provider!r}")
