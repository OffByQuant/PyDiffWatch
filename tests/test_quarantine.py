"""Confirmed-malicious packages are denylisted: DiffWatch hard-refuses to download or process them
again, and the refusal fires BEFORE any network byte is pulled. (DiffWatch already has no install
path at all — this is the canonical 'never touch' record + defense-in-depth, not the only barrier.)"""
import pytest
from pydiffwatch import quarantine, fetcher
from pydiffwatch.config import Config
from pydiffwatch.models import NewRelease


def test_known_malicious_are_quarantined():
    for p in ["cudrequest", "pythondocxx", "requestspillows"]:
        assert quarantine.is_quarantined(p)


def test_name_is_pep503_normalized():
    # PyPI treats Cud_Request / cud-request / CUDREQUEST as the same project; the denylist must too.
    assert quarantine.is_quarantined("CudRequest")
    assert quarantine.is_quarantined(" pythondocxx ")
    assert quarantine.is_quarantined("REQUESTSPILLOWS")


def test_benign_not_quarantined():
    assert not quarantine.is_quarantined("requests")
    assert not quarantine.is_quarantined("numpy")
    assert not quarantine.is_quarantined("")


def test_fetch_refuses_quarantined_without_touching_network(monkeypatch):
    # If the guard fires first, neither the PyPI JSON nor the sdist is ever requested. Make both
    # explode so the test FAILS if the guard is bypassed and a download is attempted.
    def boom(*a, **k):
        raise AssertionError("a quarantined package must NEVER hit the network")
    monkeypatch.setattr(fetcher, "_package_json", boom)
    monkeypatch.setattr(fetcher, "_download", boom)
    with pytest.raises(fetcher.RefusedToFetch):
        fetcher.fetch_artifacts(Config(), NewRelease("cudrequest", "1.0.3", 1))
