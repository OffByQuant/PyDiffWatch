import json
import pytest
from pydiffwatch.backends import (OpenAICompatibleBackend, AnthropicBackend, make_backend,
                                  ReviewUnavailable, validate_verdict)
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
