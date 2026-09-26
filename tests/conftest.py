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


@pytest.fixture
def scan_stub(monkeypatch):
    """C1 split fetch_artifacts into fetcher.download + fetcher.extract_download. Tests that hand the pipeline a
    ready ArtifactSet (or a refusal) register it here instead of building real archives."""
    import dataclasses, inspect
    from pydiffwatch import fetcher
    from pydiffwatch.models import ArtifactSet, Download
    arts = {}

    def extract(cfg, dl):
        got = arts[(dl.package, dl.version)]
        if isinstance(got, BaseException):
            raise got
        if dl.prior_version is None and got.prior_version is not None:   # the caller dropped the prior
            got = dataclasses.replace(got, prior_files={}, prior_version=None, prior_error=None)
        return got

    class _Stub:
        def dl(self, got, package=None, version=None):
            assert isinstance(got, (ArtifactSet, BaseException)), f"scan_stub.dl takes an ArtifactSet or an exception, not {got!r}"
            if isinstance(got, ArtifactSet):
                package, version = got.package, got.version
                arts[(package, version)] = got
                return Download(got.package, got.version, got.prior_version, got.is_new_package, b"", None, None,
                                got.maintainer_metadata, list(got.added_dep_findings), got.requires_dist_change,
                                got.description)
            arts[(package, version)] = got
            return Download(package, version, "0", False, b"", None, None, None, [], None, None)

        def fetch(self, fn):
            takes_attempt = any(p.name == "attempt" or p.kind is p.VAR_KEYWORD
                                for p in inspect.signature(fn).parameters.values())

            def download(cfg, rel, attempt=1):
                try:
                    got = fn(cfg, rel, attempt=attempt) if takes_attempt else fn(cfg, rel)
                except fetcher.RefusedToExtract as e:
                    return self.dl(e, rel.package, rel.version)
                return got if got is None or isinstance(got, fetcher.NoSdist) else self.dl(got)
            monkeypatch.setattr(fetcher, "download", download)

    monkeypatch.setattr(fetcher, "extract_download", extract)
    return _Stub()
