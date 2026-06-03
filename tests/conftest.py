import pytest


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "live_api: test makes real Claude API calls; needs ANTHROPIC_API_KEY (skips hermetic strip)")
    config.addinivalue_line(
        "markers",
        "live_local: test makes real calls to the local Qwen endpoint (skips hermetic network block)")


@pytest.fixture(autouse=True)
def _hermetic_reviewer(request, monkeypatch):
    """Keep the suite hermetic. The reviewer's default backend is the local Qwen endpoint (no API
    key), so stripping ANTHROPIC_API_KEY alone no longer prevents a live call — also neutralize the
    backend's only network egress so no unit/e2e test can reach a real model. Tests marked
    @pytest.mark.live_api / @pytest.mark.live_local opt out and run against the real model."""
    if request.node.get_closest_marker("live_api") or request.node.get_closest_marker("live_local"):
        return
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    def _blocked(url, payload, timeout, headers=None):
        from pydiffwatch.backends import ReviewUnavailable
        raise ReviewUnavailable("hermetic: outbound model calls are disabled in tests")
    monkeypatch.setattr("pydiffwatch.backends._urllib_post_json", _blocked, raising=True)


@pytest.fixture
def tmp_cfg(tmp_path):
    from pydiffwatch.config import Config
    # reviewer_enabled=False -> deterministic heuristic pipeline (no model, no network) for e2e tests;
    # the reviewer path has its own unit tests (test_reviewer/test_orchestrator_reviewer) and the live eval.
    return Config(db_path=tmp_path / "db.sqlite", cache_dir=tmp_path / "cache",
                  lock_path=tmp_path / "lock", reviewer_enabled=False)
