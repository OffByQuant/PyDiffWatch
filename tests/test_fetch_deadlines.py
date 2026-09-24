"""urlopen's timeout bounds each socket read, not the download: a connection that trickles bytes never
trips it, so it could hold a scan tick forever. Every PyPI download gets a total deadline, JSON metadata a
longer one plus a size cap, and XML-RPC calls a socket timeout."""
import dataclasses
import logging

import pytest

from pydiffwatch import fetcher, ingest
from pydiffwatch.config import Config


class _Trickle:
    """A response that sends 1 byte every 10 s, forever."""
    def __init__(self, clock):
        self.clock = clock

    def read1(self, n=-1):
        self.clock[0] += 10.0
        return b"x"

    def read(self, n=-1):
        return self.read1(n)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _trickling(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(fetcher.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(fetcher.urllib.request, "urlopen", lambda *a, **k: _Trickle(clock))
    return dataclasses.replace(Config(), fetch_deadline_s=120.0, packument_deadline_s=300.0), clock


def test_sdist_download_gives_up_at_the_deadline(monkeypatch):
    cfg, clock = _trickling(monkeypatch)
    with pytest.raises(TimeoutError):
        fetcher._download("https://files.pythonhosted.org/p/x-1.0.tar.gz", cfg)
    assert clock[0] <= 130.0


def test_package_metadata_gets_the_longer_deadline(monkeypatch):
    cfg, clock = _trickling(monkeypatch)
    with pytest.raises(TimeoutError):
        fetcher._package_json("x", cfg)
    assert 290.0 <= clock[0] <= 310.0


def test_package_metadata_has_a_size_cap(monkeypatch):
    class Big:
        def read1(self, n=-1):
            return b"x" * 65536

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    monkeypatch.setattr(fetcher.urllib.request, "urlopen", lambda *a, **k: Big())
    with pytest.raises(fetcher.RefusedToFetch):
        fetcher._package_json("x", dataclasses.replace(Config(), max_metadata_bytes=1_000_000))


def test_xmlrpc_calls_have_a_socket_timeout(monkeypatch):
    seen = {}

    class Proxy:
        def __init__(self, url, transport=None, **k):
            seen["timeout"] = getattr(transport, "timeout", None)

        def changelog_since_serial(self, s):
            return []
    monkeypatch.setattr(ingest.xmlrpc.client, "ServerProxy", Proxy)
    ingest.changes_since(dataclasses.replace(Config(), fetch_timeout_s=30.0), 1)
    assert seen["timeout"] == 30.0


def test_a_failed_changelog_call_is_logged_and_keeps_the_cursor(monkeypatch, caplog):
    class Proxy:
        def __init__(self, *a, **k):
            pass

        def changelog_since_serial(self, s):
            raise TimeoutError("timed out")
    monkeypatch.setattr(ingest.xmlrpc.client, "ServerProxy", Proxy)
    with caplog.at_level(logging.WARNING):
        assert ingest.changes_since(Config(), 1) == []
    assert "timed out" in caplog.text


def test_a_retry_scales_only_the_packument_and_sdist_deadlines(monkeypatch):
    # Fix round 2: requires_dist and dependency lookups swallow every error (-> [] / {}), so a longer deadline
    # can't turn one into a success; scaling them made one k=4 row worth ~4.3 h. Only the package JSON and the
    # two sdist downloads get x attempt.
    import io, json
    from pydiffwatch import orchestrator
    from pydiffwatch.models import NewRelease
    cfg = Config()
    budgets = []
    deps = [f"zqxv-internal-thing-{i}" for i in range(12)]
    meta = {"info": {"version": "2.0", "requires_dist": deps},
            "releases": {"1.0": [{"packagetype": "sdist", "url": "https://files/p-1.0.tar.gz",
                                  "upload_time_iso_8601": "2020-01-01T00:00:00Z"}],
                         "2.0": [{"packagetype": "sdist", "url": "https://files/p-2.0.tar.gz",
                                  "upload_time_iso_8601": "2021-01-01T00:00:00Z"}]}}

    class R(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def urlopen(u, timeout=None):
        url = u if isinstance(u, str) else u.full_url
        if url.endswith("/pypi/p/json"):
            return R(json.dumps(meta).encode())
        if url.endswith("/pypi/p/1.0/json"):
            return R(json.dumps({"info": {"requires_dist": []}}).encode())
        if "/pypi/" in url:
            return R(json.dumps({"releases": {}}).encode())
        return R(b"x")

    def read_body(r, cfg, limit=None, deadline=None):
        budgets.append(deadline or cfg.fetch_deadline_s)
        return r.read()
    monkeypatch.setattr(fetcher.urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(fetcher, "read_body", read_body)
    monkeypatch.setattr(fetcher, "extract_sdist", lambda b, c: ({}, []))
    monkeypatch.setattr(fetcher.egress, "assert_web_scheme", lambda u: None)
    res = orchestrator._fetch_one(cfg, NewRelease("p", "2.0", 1), 4)
    assert not isinstance(res, Exception), res
    f, p = cfg.fetch_deadline_s, cfg.packument_deadline_s
    assert budgets == [p * 4, f * 4, f * 4, p] + [p] * cfg.max_dep_lookups   # packument, new, prior, deps
    assert sum(budgets) == 5_460
    budgets.clear()
    orchestrator._fetch_one(cfg, NewRelease("p", "2.0", 1))                  # attempt 1: as configured
    assert budgets == [p, f, f, p] + [p] * cfg.max_dep_lookups
