import dataclasses
import email.message
import gzip
import io
import json
import urllib.error

import pytest

from pydiffwatch import ingest
from pydiffwatch.config import Config


def _cfg(tmp_path):
    lock_path = tmp_path / "state" / "pydiffwatch.lock"
    lock_path.parent.mkdir(parents=True)
    return dataclasses.replace(Config(), lock_path=lock_path)


def _index(entries, meta_serial):
    return json.dumps({"meta": {"_last-serial": meta_serial, "api-version": "1.4"},
                       "projects": [{"_last-serial": s, "name": n} for s, n in entries]}).encode()


def _hdrs(**kv):
    m = email.message.Message()
    for k, v in kv.items():
        m[k.replace("_", "-")] = v
    return m


def test_changed_lists_projects_above_the_cursor_in_serial_order():
    text = _index([(5, "alpha-demo"), (12, "beta-demo"), (9, "gamma-demo"), (12, "delta-demo")], 12).decode()
    assert ingest._changed(text, 8) == (12, [(9, "gamma-demo"), (12, "beta-demo"), (12, "delta-demo")])


def test_changed_ignores_malformed_entries_and_needs_a_meta_serial():
    text = ('{"meta": {"_last-serial": 30}, "projects": [{"_last-serial": 20, "name": "ok-demo"}, '
            '{"_last-serial": "x", "name": "bad-demo"}, {"name": "noserial-demo"}, {"_last-serial": 25}]}')
    assert ingest._changed(text, 0) == (30, [(20, "ok-demo")])
    with pytest.raises(ValueError):
        ingest._changed('{"projects": []}', 0)


def test_index_is_fetched_gzipped_cached_and_reused_on_304(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    body = gzip.compress(_index([(3, "alpha-demo")], 3))
    calls = []

    def fake_get(cfg_, url, headers, limit, deadline):
        calls.append(headers)
        if "If-None-Match" in headers:
            raise urllib.error.HTTPError(url, 304, "Not Modified", _hdrs(), io.BytesIO(b""))
        return 200, _hdrs(Content_Encoding="gzip", ETag='"v1"'), body
    monkeypatch.setattr(ingest, "_get", fake_get)
    first = ingest._index_text(cfg)
    second = ingest._index_text(cfg)
    assert first == second and '"alpha-demo"' in first
    assert calls[0]["Accept"] == ingest.INDEX_ACCEPT and "If-None-Match" not in calls[0]
    assert calls[1]["If-None-Match"] == '"v1"'


def test_an_uncompressed_index_body_is_accepted(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    monkeypatch.setattr(ingest, "_get", lambda *a: (200, _hdrs(), _index([(4, "alpha-demo")], 4)))
    assert ingest._changed(ingest._index_text(cfg), 0) == (4, [(4, "alpha-demo")])


def test_a_decoded_index_over_the_cap_is_refused(tmp_path, monkeypatch):
    cfg = dataclasses.replace(_cfg(tmp_path), max_index_bytes=1_000)
    bomb = gzip.compress(b" " * 50_000)
    monkeypatch.setattr(ingest, "_get", lambda *a: (200, _hdrs(Content_Encoding="gzip"), bomb))
    with pytest.raises(ValueError):
        ingest._index_text(cfg)


def test_current_serial_reads_the_index_header(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    monkeypatch.setattr(ingest, "_head_serial", lambda cfg_: 41_000_000)
    assert ingest.current_serial(cfg) == 41_000_000

    def boom(cfg_):
        raise OSError("down")
    monkeypatch.setattr(ingest, "_head_serial", boom)
    assert ingest.current_serial(cfg) is None
