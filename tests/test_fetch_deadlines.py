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
