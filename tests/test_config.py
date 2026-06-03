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


def test_load_config_missing_file_returns_defaults(tmp_path):
    cfg = load_config(tmp_path / "nope.toml")
    assert cfg.reviewer.base_url == "http://localhost:8000/v1"
