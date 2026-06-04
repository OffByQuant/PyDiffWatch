import json
import pytest
from pydiffwatch.backends import (OpenAICompatibleBackend, AnthropicBackend, make_backend,
                                  ReviewUnavailable, validate_verdict)
# Captured at import, before the autouse hermetic fixture rebinds the module attribute to a blocker.
from pydiffwatch.backends import _urllib_post_json as _real_urllib_post_json
from pydiffwatch.config import Config, ReviewerConfig

SCHEMA = {"type": "object", "properties": {
    "classification": {"type": "string", "enum": ["malicious", "suspicious", "benign"]},
    "confidence": {"type": "number"}}, "required": ["classification", "confidence"]}


def _ok():
    return {"choices": [{"message": {"content": json.dumps({"classification": "benign", "confidence": 0.9})}}]}


def test_json_schema_mode_sets_response_format():
    cap = {}

    def post(url, payload, timeout, headers=None):
        cap.update(payload)
        return _ok()
    b = OpenAICompatibleBackend("http://x/v1", "m", structured_output="json_schema", post=post)
    b.complete(model="m", system="s", user_text="u", schema=SCHEMA, max_tokens=10)
    assert cap["response_format"]["type"] == "json_schema"


def test_json_object_mode_uses_loose_format():
    cap = {}

    def post(url, payload, timeout, headers=None):
        cap.update(payload)
        return _ok()
    b = OpenAICompatibleBackend("http://x/v1", "m", structured_output="json_object", post=post)
    b.complete(model="m", system="s", user_text="u", schema=SCHEMA, max_tokens=10)
    assert cap["response_format"] == {"type": "json_object"}


def test_none_mode_sends_no_response_format():
    cap = {}

    def post(url, payload, timeout, headers=None):
        cap.update(payload)
        return _ok()
    b = OpenAICompatibleBackend("http://x/v1", "m", structured_output="none", post=post)
    b.complete(model="m", system="s", user_text="u", schema=SCHEMA, max_tokens=10)
    assert "response_format" not in cap


def test_api_key_header_set_from_env(monkeypatch):
    monkeypatch.setenv("MYKEY", "sek-123")
    cap = {}

    def post(url, payload, timeout, headers=None):
        cap["headers"] = headers or {}
        return _ok()
    b = OpenAICompatibleBackend("http://x/v1", "m", api_key_env="MYKEY", post=post)
    b.complete(model="m", system="s", user_text="u", schema=SCHEMA, max_tokens=10)
    assert cap["headers"].get("Authorization") == "Bearer sek-123"


def test_no_api_key_env_sends_no_auth_header():
    cap = {}

    def post(url, payload, timeout, headers=None):
        cap["headers"] = headers or {}
        return _ok()
    b = OpenAICompatibleBackend("http://x/v1", "m", post=post)
    b.complete(model="m", system="s", user_text="u", schema=SCHEMA, max_tokens=10)
    assert "Authorization" not in cap["headers"]


def test_invalid_verdict_maps_to_review_unavailable():
    def post(url, payload, timeout, headers=None):
        return {"choices": [{"message": {"content": json.dumps({"classification": "safe", "confidence": 1})}}]}
    b = OpenAICompatibleBackend("http://x/v1", "m", structured_output="none", post=post)
    with pytest.raises(ReviewUnavailable):
        b.complete(model="m", system="s", user_text="u", schema=SCHEMA, max_tokens=10)


def test_non_json_content_maps_to_review_unavailable():
    def post(url, payload, timeout, headers=None):
        return {"choices": [{"message": {"content": "I cannot help with that."}}]}
    b = OpenAICompatibleBackend("http://x/v1", "m", structured_output="none", post=post)
    with pytest.raises(ReviewUnavailable):
        b.complete(model="m", system="s", user_text="u", schema=SCHEMA, max_tokens=10)


def test_validate_verdict_accepts_valid():
    validate_verdict({"classification": "benign", "confidence": 0.9}, SCHEMA)   # no raise


def test_validate_verdict_rejects_missing_key():
    with pytest.raises(ReviewUnavailable):
        validate_verdict({"confidence": 0.9}, SCHEMA)


def test_validate_verdict_rejects_bad_enum():
    with pytest.raises(ReviewUnavailable):
        validate_verdict({"classification": "safe", "confidence": 0.9}, SCHEMA)


def test_validate_verdict_clamps_unknown_attack_type_instead_of_rejecting():
    # attack_type is informational; an out-of-enum value must NOT sink the verdict (it is clamped to
    # "none" at Verdict construction). classification stays a hard failure — it is the decision field.
    schema = {"type": "object",
              "properties": {"classification": {"type": "string", "enum": ["malicious", "benign"]},
                             "attack_type": {"type": "string", "enum": ["typosquat", "none"]}},
              "required": ["classification", "attack_type"]}
    validate_verdict({"classification": "benign", "attack_type": "data-theft"}, schema)   # no raise
    with pytest.raises(ReviewUnavailable):
        validate_verdict({"classification": "safe", "attack_type": "none"}, schema)


def test_validate_verdict_clamps_unknown_recommended_action_instead_of_rejecting():
    # recommended_action is clamped toward caution downstream (reviewer.py), so an out-of-enum value
    # must pass client validation rather than discard a verdict whose classification is sound.
    schema = {"type": "object",
              "properties": {"classification": {"type": "string", "enum": ["malicious", "benign"]},
                             "recommended_action": {"type": "string",
                                                    "enum": ["report-to-pypi", "monitor", "dismiss"]}},
              "required": ["classification", "recommended_action"]}
    validate_verdict({"classification": "benign", "recommended_action": "block_and_report"}, schema)  # no raise


def test_missing_key_error_hints_truncation_fix():
    with pytest.raises(ReviewUnavailable, match="max_output_tokens"):
        validate_verdict({"confidence": 0.9}, SCHEMA)   # missing classification


def test_http_400_error_hints_json_object():
    # The DeepSeek landmine: strict json_schema 400s. The error must tell the operator the fix.
    class _HTTPErr(Exception):
        code = 400

    def post(url, payload, timeout, headers=None):
        raise _HTTPErr("Bad Request")
    b = OpenAICompatibleBackend("http://x/v1", "m", post=post)
    with pytest.raises(ReviewUnavailable, match="json_object"):
        b.complete(model="m", system="s", user_text="u", schema=SCHEMA, max_tokens=10)


def test_connection_error_hints_base_url():
    def post(url, payload, timeout, headers=None):
        raise ConnectionRefusedError("Connection refused")
    b = OpenAICompatibleBackend("http://x/v1", "m", post=post)
    with pytest.raises(ReviewUnavailable, match="base_url"):
        b.complete(model="m", system="s", user_text="u", schema=SCHEMA, max_tokens=10)


def test_non_json_content_hints_structured_output():
    def post(url, payload, timeout, headers=None):
        return {"choices": [{"message": {"content": "I cannot help with that."}}]}
    b = OpenAICompatibleBackend("http://x/v1", "m", structured_output="none", post=post)
    with pytest.raises(ReviewUnavailable, match="structured_output"):
        b.complete(model="m", system="s", user_text="u", schema=SCHEMA, max_tokens=10)


def test_default_post_sets_user_agent_header(monkeypatch):
    # Some API gateways (Cloudflare/WAF) 403 the stdlib default "Python-urllib/3.x" UA. Send an explicit
    # one matching fetcher.py's egress identity.
    from pydiffwatch import backends
    captured = {}

    class _Resp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return b'{"ok": true}'

    def fake_urlopen(req, timeout=None):
        captured["req"] = req
        return _Resp()
    monkeypatch.setattr(backends.urllib.request, "urlopen", fake_urlopen)
    _real_urllib_post_json("http://x/v1/chat/completions", {"a": 1}, 5.0)
    assert captured["req"].get_header("User-agent") == "diffwatch/0.1"


def test_extra_body_merged_into_payload():
    # Provider-specific knobs (e.g. DeepSeek's reasoning toggle) are passed verbatim into the request.
    cap = {}

    def post(url, payload, timeout, headers=None):
        cap.update(payload)
        return _ok()
    b = OpenAICompatibleBackend("http://x/v1", "m", structured_output="json_object", post=post,
                                extra_body={"reasoning": {"enabled": False}})
    b.complete(model="m", system="s", user_text="u", schema=SCHEMA, max_tokens=10)
    assert cap["reasoning"] == {"enabled": False}


def test_extra_body_cannot_clobber_core_payload_fields():
    # extra_body is operator config, but a stray reserved key must not override the model, the
    # injection-delimited messages, max_tokens, or the structured-output response_format.
    cap = {}

    def post(url, payload, timeout, headers=None):
        cap.update(payload)
        return _ok()
    b = OpenAICompatibleBackend("http://x/v1", "m", structured_output="json_object", post=post,
                                extra_body={"model": "evil", "messages": [], "max_tokens": 1})
    b.complete(model="m", system="s", user_text="u", schema=SCHEMA, max_tokens=10)
    assert cap["model"] == "m" and cap["max_tokens"] == 10 and len(cap["messages"]) == 2


def test_make_backend_openai_from_config():
    cfg = Config(reviewer=ReviewerConfig(provider="openai", base_url="http://h/v1", model="m"))
    b = make_backend(cfg)
    assert isinstance(b, OpenAICompatibleBackend) and b.primary_model == "m"


def test_make_backend_anthropic_from_config():
    cfg = Config(reviewer=ReviewerConfig(provider="anthropic", model="claude-sonnet-4-6"))
    b = make_backend(cfg, client=object())   # injected client avoids SDK import / key
    assert isinstance(b, AnthropicBackend) and b.primary_model == "claude-sonnet-4-6"


def test_make_backend_unknown_provider_raises():
    cfg = Config(reviewer=ReviewerConfig(provider="weirdai"))
    with pytest.raises(ValueError):
        make_backend(cfg)
