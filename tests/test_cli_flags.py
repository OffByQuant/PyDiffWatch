"""--model / --endpoint point the reviewer at an OpenAI-compatible server without a config file, and
--recent's help counts PyPI changelog events (one release is several events), never releases."""
import argparse
import sys

import pytest

from pydiffwatch import __main__ as cli


def _args(**kw):
    return argparse.Namespace(**{"config": None, "model": None, "endpoint": None, **kw})


def test_model_alone_uses_the_default_local_endpoint():
    cfg = cli._cfg(_args(model="gemma-singleshot"))
    rc = cfg.reviewer
    assert (rc.provider, rc.model, rc.base_url) == ("openai", "gemma-singleshot", "http://localhost:8000/v1")
    assert cfg.reviewer_enabled


def test_endpoint_points_at_a_model_on_another_machine():
    rc = cli._cfg(_args(model="gemma-singleshot", endpoint="http://192.0.2.10:8000/v1")).reviewer
    assert (rc.model, rc.base_url) == ("gemma-singleshot", "http://192.0.2.10:8000/v1")


def test_flags_override_the_config_file(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text('reviewer_enabled = false\n[reviewer]\nprovider = "anthropic"\n'
                 'base_url = "http://localhost:9999/v1"\nmodel = "old"\ntimeout = 120.0\n')
    cfg = cli._cfg(_args(config=str(p), model="new"))
    rc = cfg.reviewer
    assert (rc.provider, rc.model, rc.base_url, rc.timeout) == ("openai", "new", "http://localhost:9999/v1", 120.0)
    assert cfg.reviewer_enabled


def test_no_flags_leaves_the_config_alone():
    rc = cli._cfg(_args()).reviewer
    assert rc.model == "qwen-singleshot"


def test_flags_do_not_bypass_the_missing_config_check(tmp_path):
    with pytest.raises(SystemExit, match="nope.toml"):
        cli._cfg(_args(config=str(tmp_path / "nope.toml"), model="new"))


@pytest.mark.parametrize("cmd", ["run", "watch"])
def test_recent_help_counts_changelog_events_not_releases(cmd, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["pydiffwatch", cmd, "--help"])
    with pytest.raises(SystemExit):
        cli.main()
    help_text = " ".join(capsys.readouterr().out.split())
    recent = help_text[help_text.index("--recent N"):]
    assert "changelog events" in recent
    assert "N releases" not in recent and "N PyPI releases" not in recent


def _keyed(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text('[reviewer]\nbase_url = "https://api.example.com/v1"\napi_key_env = "OPENAI_API_KEY"\n')
    return str(p)


def test_endpoint_to_another_host_does_not_carry_the_configs_api_key(tmp_path):
    # Final review: dataclasses.replace kept api_key_env, so --endpoint sent the config's key to the new host.
    rc = cli._cfg(_args(config=_keyed(tmp_path), endpoint="http://192.0.2.10:8000/v1")).reviewer
    assert rc.base_url == "http://192.0.2.10:8000/v1" and rc.api_key_env is None


def test_endpoint_equal_to_the_configs_keeps_its_api_key(tmp_path):
    rc = cli._cfg(_args(config=_keyed(tmp_path), endpoint="https://api.example.com/v1", model="m")).reviewer
    assert rc.api_key_env == "OPENAI_API_KEY"


def test_model_alone_keeps_the_configs_api_key(tmp_path):
    assert cli._cfg(_args(config=_keyed(tmp_path), model="m")).reviewer.api_key_env == "OPENAI_API_KEY"


def _no_scan(monkeypatch, seen=None):
    """Stub everything main() would reach for, so a test can never scan PyPI or touch a real database."""
    seen = {} if seen is None else seen
    monkeypatch.setattr(cli, "_cfg", lambda args: cli.Config())
    monkeypatch.setattr(cli.egress, "install_guard", lambda cfg: None)
    monkeypatch.setattr(cli, "run_once", lambda cfg, **k: seen.setdefault("recent", k["recent"]) and 0)
    monkeypatch.setattr(cli, "watch", lambda cfg, **k: seen.setdefault("recent", k["recent"]) and 0)
    monkeypatch.setattr(cli, "export_dashboard", lambda cfg, **k: cli.Config().db_path)
    return seen


@pytest.mark.parametrize("cmd", ["run", "watch"])
def test_negative_recent_is_rejected(cmd, monkeypatch, capsys):
    _no_scan(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["pydiffwatch", cmd, "--recent", "-5"])
    with pytest.raises(SystemExit) as e:
        cli.main()
    assert e.value.code == 2 and "--recent" in capsys.readouterr().err


@pytest.mark.parametrize("cmd", ["run", "watch"])
def test_recent_zero_is_allowed_and_means_start_now(cmd, monkeypatch):
    # As npmDiffWatch: 0 is accepted, and run_once treats it like no --recent (seed the cursor to now).
    seen = _no_scan(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["pydiffwatch", cmd, "--recent", "0"])
    cli.main()
    assert seen["recent"] == 0


def test_a_directory_as_config_exits_cleanly(tmp_path):
    with pytest.raises(SystemExit, match=str(tmp_path)):
        cli._cfg(_args(config=str(tmp_path)))
