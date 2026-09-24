import pytest
import textwrap
from pydiffwatch.config import Config, ReviewerConfig, load_config


def test_default_endpoint_is_not_a_lan_ip():
    assert "192.168" not in Config().reviewer.base_url
    assert Config().reviewer.base_url == "http://localhost:8000/v1"


def test_default_reviewer_is_openai_compatible():
    rc = Config().reviewer
    assert rc.provider == "openai" and rc.structured_output == "json_schema"
    assert rc.api_key_env is None


def test_containment_caps_preserved():
    c = Config()
    assert c.max_download_bytes == 50 * 1024 * 1024
    assert c.max_members == 2000 and c.fetch_concurrency == 4
    assert c.threshold_t == 40.0


def test_load_config_from_toml(tmp_path):
    p = tmp_path / "pydiffwatch.toml"
    p.write_text(textwrap.dedent('''
        threshold_t = 50
        [reviewer]
        provider = "anthropic"
        model = "claude-sonnet-4-6"
        api_key_env = "ANTHROPIC_API_KEY"
        structured_output = "json_schema"
    '''))
    cfg = load_config(p)
    assert cfg.threshold_t == 50
    assert cfg.reviewer.provider == "anthropic"
    assert cfg.reviewer.model == "claude-sonnet-4-6"
    assert cfg.reviewer.api_key_env == "ANTHROPIC_API_KEY"


def test_load_config_missing_file_raises(tmp_path):
    # A mistyped -c path must fail loudly, never silently run on built-in defaults.
    with pytest.raises(FileNotFoundError, match="nope.toml"):
        load_config(tmp_path / "nope.toml")


def test_cli_missing_config_exits_with_error(tmp_path):
    import argparse
    from pydiffwatch.__main__ import _cfg
    with pytest.raises(SystemExit, match="nope.toml"):
        _cfg(argparse.Namespace(config=str(tmp_path / "nope.toml"), model=None, endpoint=None))


def test_cli_without_config_uses_defaults():
    import argparse
    from pydiffwatch.__main__ import _cfg
    assert _cfg(argparse.Namespace(config=None, model=None, endpoint=None)) == Config()


def test_default_max_output_tokens_fits_reasoning_models():
    # Reasoning models (e.g. DeepSeek) count thinking tokens inside the output budget; a small cap
    # truncates the JSON before all fields emit. The default must leave room for reasoning + verdict.
    assert ReviewerConfig().max_output_tokens == 32000


def test_default_extra_body_is_empty():
    assert ReviewerConfig().extra_body == {}


def test_load_config_reads_reviewer_extra_body(tmp_path):
    # Provider-specific request knobs (e.g. DeepSeek's reasoning toggle) load from a nested TOML table.
    p = tmp_path / "pydiffwatch.toml"
    p.write_text(textwrap.dedent('''
        [reviewer]
        provider = "openai"
        [reviewer.extra_body]
        reasoning = { enabled = false }
    '''))
    cfg = load_config(p)
    assert cfg.reviewer.extra_body == {"reasoning": {"enabled": False}}
