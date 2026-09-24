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
