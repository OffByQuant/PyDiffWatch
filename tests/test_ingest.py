import dataclasses
import email.message
import gzip
import io
import json
import logging
import urllib.error

import pytest

from pydiffwatch import fetcher, ingest
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


def _pj(name, serial, versions):
    """A /pypi/<name>/json body: versions = {ver: [(packagetype, upload_iso), ...]}."""
    return json.dumps({"info": {"name": name}, "last_serial": serial,
                       "releases": {v: [{"packagetype": t, "upload_time_iso_8601": ts} for t, ts in files]
                                    for v, files in versions.items()}}).encode()


def _serve(monkeypatch, index, projects, fail=()):
    """index: bytes of /simple/; projects: {name: (header_serial, body_bytes)} or name -> 404 if missing."""
    def fake_get(cfg_, url, headers, limit, deadline):
        if url.endswith("/simple/"):
            return 200, _hdrs(), index
        name = url.split("/pypi/")[1].split("/json")[0]
        if name in fail:
            raise OSError("reset")
        if name not in projects:
            raise urllib.error.HTTPError(url, 404, "Not Found", _hdrs(), io.BytesIO(b""))
        serial, body = projects[name]
        return 200, _hdrs(X_PyPI_Last_Serial=str(serial)), body
    monkeypatch.setattr(ingest, "_get", fake_get)


T0 = "2026-09-28T10:00:00Z"


def test_new_versions_at_or_after_the_floor_are_listed_old_history_is_not(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    old = {f"0.{i}": [("sdist", "2020-01-01T00:00:00Z")] for i in range(300)}
    _serve(monkeypatch, _index([(50, "alpha-demo")], 50),
           {"alpha-demo": (50, _pj("Alpha-Demo", 50, {**old, "1.0": [("bdist_wheel", "2026-09-28T10:05:00Z"),
                                                                       ("sdist", "2026-09-28T10:06:00Z")]}))})
    got = ingest.changes_since(cfg, 40, floor=T0, stage=lambda p, v: None)
    assert [(r.package, r.version, r.serial, r.new_release, r.sdist_upload) for r in got] == \
        [("Alpha-Demo", "1.0", 50, True, False)]
    assert got.ceiling == 50
    assert got.complete is True


def test_known_and_terminal_versions_are_not_relisted(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    _serve(monkeypatch, _index([(50, "alpha-demo")], 50),
           {"alpha-demo": (50, _pj("Alpha-Demo", 50, {"1.0": [("sdist", "2026-09-28T10:05:00Z")]}))})
    got = ingest.changes_since(cfg, 40, floor=T0, stage=lambda p, v: "scanned_clean")
    assert list(got) == [] and got.ceiling == 50


def test_an_sdist_arriving_for_a_wheel_only_release_is_an_sdist_upload(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    _serve(monkeypatch, _index([(60, "alpha-demo")], 60),
           {"alpha-demo": (60, _pj("Alpha-Demo", 60, {"2.0": [("bdist_wheel", "2026-01-01T00:00:00Z"),
                                                            ("sdist", "2026-09-28T11:00:00Z")]}))})
    got = ingest.changes_since(cfg, 40, floor=T0, stage=lambda p, v: "no_sdist_wait")
    assert [(r.version, r.new_release, r.sdist_upload) for r in got] == [("2.0", False, True)]


def test_a_stale_project_json_is_listed_but_holds_the_cursor_below_it(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    _serve(monkeypatch, _index([(50, "alpha-demo"), (70, "beta-demo")], 70),
           {"alpha-demo": (45, _pj("Alpha-Demo", 45, {"1.0": [("sdist", "2026-09-28T10:05:00Z")]})),
            "beta-demo": (70, _pj("Beta-Demo", 70, {"3.0": [("sdist", "2026-09-28T10:07:00Z")]}))})
    got = ingest.changes_since(cfg, 40, floor=T0, stage=lambda p, v: None)
    assert [(r.package, r.serial) for r in got] == [("Alpha-Demo", 50), ("Beta-Demo", 70)]
    assert got.ceiling == 49
    assert got.complete is False


def test_a_failed_project_holds_the_cursor_and_a_404_project_resolves_empty(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    _serve(monkeypatch, _index([(50, "gone-demo"), (60, "flaky-demo"), (70, "beta-demo")], 70),
           {"beta-demo": (70, _pj("Beta-Demo", 70, {"3.0": [("sdist", "2026-09-28T10:07:00Z")]}))},
           fail={"flaky-demo"})
    got = ingest.changes_since(cfg, 40, floor=T0, stage=lambda p, v: None)
    assert [r.package for r in got] == ["Beta-Demo"] and got.ceiling == 59
    assert got.complete is False


def test_the_project_cap_holds_the_cursor_below_the_first_project_left_out(tmp_path, monkeypatch):
    cfg = dataclasses.replace(_cfg(tmp_path), max_projects_per_run=1)
    _serve(monkeypatch, _index([(50, "alpha-demo"), (70, "beta-demo")], 70),
           {"alpha-demo": (50, _pj("Alpha-Demo", 50, {"1.0": [("sdist", "2026-09-28T10:05:00Z")]})),
            "beta-demo": (70, _pj("Beta-Demo", 70, {"3.0": [("sdist", "2026-09-28T10:07:00Z")]}))})
    got = ingest.changes_since(cfg, 40, floor=T0, stage=lambda p, v: None)
    assert [r.package for r in got] == ["Alpha-Demo"] and got.ceiling == 69
    assert got.complete is False


def test_the_release_cap_cuts_in_serial_order_and_lowers_the_ceiling(tmp_path, monkeypatch):
    cfg = dataclasses.replace(_cfg(tmp_path), max_releases_per_run=2)
    _serve(monkeypatch, _index([(50, "alpha-demo"), (70, "beta-demo")], 70),
           {"alpha-demo": (50, _pj("Alpha-Demo", 50, {"1.0": [("sdist", "2026-09-28T10:05:00Z")],
                                                       "1.1": [("sdist", "2026-09-28T10:06:00Z")]})),
            "beta-demo": (70, _pj("Beta-Demo", 70, {"3.0": [("sdist", "2026-09-28T10:07:00Z")]}))})
    got = ingest.changes_since(cfg, 40, floor=T0, stage=lambda p, v: None)
    assert [(r.package, r.version) for r in got] == [("Alpha-Demo", "1.0"), ("Alpha-Demo", "1.1")]
    assert got.ceiling == 69


def test_an_index_failure_returns_nothing_and_no_ceiling(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)

    def boom(*a):
        raise OSError("503")
    monkeypatch.setattr(ingest, "_get", boom)
    got = ingest.changes_since(cfg, 40, floor=T0, stage=lambda p, v: None)
    assert list(got) == [] and got.ceiling is None
    monkeypatch.setattr(ingest, "_get", lambda *a: (200, _hdrs(), b"<html>Service Unavailable</html>"))
    got = ingest.changes_since(cfg, 40, floor=T0, stage=lambda p, v: None)
    assert list(got) == [] and got.ceiling is None


def test_no_floor_accepts_every_unseen_version(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    _serve(monkeypatch, _index([(50, "alpha-demo")], 50),
           {"alpha-demo": (50, _pj("Alpha-Demo", 50, {"0.1": [("sdist", "2019-01-01T00:00:00Z")]}))})
    got = ingest.changes_since(cfg, 0, floor=None, stage=lambda p, v: None)
    assert [r.version for r in got] == ["0.1"]


def test_stage_is_only_called_on_the_calling_thread(tmp_path, monkeypatch):
    import threading
    cfg = dataclasses.replace(_cfg(tmp_path), fetch_concurrency=4)
    main = threading.get_ident()
    seen = set()
    _serve(monkeypatch, _index([(50 + i, f"p{i}-demo") for i in range(8)], 57),
           {f"p{i}-demo": (50 + i, _pj(f"P{i}-Demo", 50 + i, {"1.0": [("sdist", "2026-09-28T10:05:00Z")]}))
            for i in range(8)})

    def stage(p, v):
        seen.add(threading.get_ident())
        return None
    ingest.changes_since(cfg, 40, floor=T0, stage=stage)
    assert seen == {main}


def test_a_project_permanently_over_the_metadata_cap_resolves_empty_without_freezing_the_cursor(tmp_path, monkeypatch, caplog):
    # R1: RefusedToFetch (JSON over max_metadata_bytes) must not lower the ceiling or repeat forever.
    cfg = _cfg(tmp_path)

    def fake_get(cfg_, url, headers, limit, deadline):
        if url.endswith("/simple/"):
            return 200, _hdrs(), _index([(50, "huge-demo"), (60, "beta-demo")], 60)
        if "huge-demo" in url:
            raise fetcher.RefusedToFetch("download-size")
        return 200, _hdrs(X_PyPI_Last_Serial="60"), _pj("Beta-Demo", 60, {"3.0": [("sdist", "2026-09-28T10:07:00Z")]})
    monkeypatch.setattr(ingest, "_get", fake_get)
    with caplog.at_level(logging.ERROR):
        got = ingest.changes_since(cfg, 40, floor=T0, stage=lambda p, v: None)
    assert [r.package for r in got] == ["Beta-Demo"]
    assert got.ceiling == 60
    assert got.complete is True
    assert any(r.levelno == logging.ERROR and "huge-demo" in r.getMessage() for r in caplog.records)


def test_a_truncated_gzip_index_body_is_contained(tmp_path, monkeypatch, caplog):
    # R4: a corrupt/truncated gzip body must not raise past changes_since.
    cfg = _cfg(tmp_path)
    body = gzip.compress(_index([(5, "alpha-demo")], 5))[:40]
    monkeypatch.setattr(ingest, "_get", lambda *a: (200, _hdrs(Content_Encoding="gzip"), body))
    with caplog.at_level(logging.WARNING):
        got = ingest.changes_since(cfg, 0, floor=T0, stage=lambda p, v: None)
    assert list(got) == [] and got.ceiling is None
    assert any(r.levelno == logging.WARNING for r in caplog.records)


def test_ingest_no_longer_uses_xml_rpc():
    import pathlib
    src = pathlib.Path(ingest.__file__).read_text()
    assert "xmlrpc" not in src and "changelog_since_serial" not in src
    toml = (pathlib.Path(ingest.__file__).parent.parent / "pyproject.toml").read_text()
    assert "defusedxml" not in toml


# ---- final fix pass: C2 re-list interrupted releases, I1 bounded holds, P1 refused report, I2 truncation ----

def test_an_interrupted_release_is_relisted_and_a_terminal_one_is_not(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    _serve(monkeypatch, _index([(50, "alpha-demo")], 50),
           {"alpha-demo": (50, _pj("Alpha-Demo", 50, {"1.0": [("sdist", "2019-01-01T00:00:00Z")],
                                                       "1.1": [("sdist", "2019-01-02T00:00:00Z")]}))})
    stages = {"1.0": "ingested", "1.1": "triaged"}
    got = ingest.changes_since(cfg, 40, floor=T0, stage=lambda p, v: stages[v],
                               terminal=frozenset({"triaged"}))
    assert [(r.package, r.version, r.serial, r.new_release, r.sdist_upload) for r in got] == \
        [("Alpha-Demo", "1.0", 50, True, False)]
    assert got.ceiling == 50
    assert list(ingest.changes_since(cfg, 40, floor=T0, stage=lambda p, v: stages[v])) == []


def test_the_wheel_only_branch_still_wins_when_terminal_is_given(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    _serve(monkeypatch, _index([(60, "alpha-demo")], 60),
           {"alpha-demo": (60, _pj("Alpha-Demo", 60, {"2.0": [("bdist_wheel", "2026-01-01T00:00:00Z"),
                                                            ("sdist", "2026-09-28T11:00:00Z")]}))})
    got = ingest.changes_since(cfg, 40, floor=T0, stage=lambda p, v: "no_sdist_wait", terminal=frozenset())
    assert [(r.version, r.new_release, r.sdist_upload) for r in got] == [("2.0", False, True)]


def test_failed_and_stale_projects_are_reported_as_held(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    _serve(monkeypatch, _index([(50, "stale-demo"), (60, "flaky-demo"), (70, "beta-demo")], 70),
           {"stale-demo": (45, _pj("Stale-Demo", 45, {"1.0": [("sdist", "2026-09-28T10:05:00Z")]})),
            "beta-demo": (70, _pj("Beta-Demo", 70, {"3.0": [("sdist", "2026-09-28T10:07:00Z")]}))},
           fail={"flaky-demo"})
    got = ingest.changes_since(cfg, 40, floor=T0, stage=lambda p, v: None)
    assert [(n, s) for n, s, _ in got.held] == [("stale-demo", 50), ("flaky-demo", 60)]
    assert all(isinstance(why, str) and why for _, _, why in got.held)
    assert got.ceiling == 49


def test_a_released_hold_is_still_fetched_but_no_longer_lowers_the_ceiling(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    fetched = []
    _serve(monkeypatch, _index([(50, "stale-demo"), (60, "flaky-demo"), (70, "beta-demo")], 70),
           {"stale-demo": (45, _pj("Stale-Demo", 45, {"1.0": [("sdist", "2026-09-28T10:05:00Z")]})),
            "beta-demo": (70, _pj("Beta-Demo", 70, {"3.0": [("sdist", "2026-09-28T10:07:00Z")]}))},
           fail={"flaky-demo"})
    real = ingest._get
    monkeypatch.setattr(ingest, "_get", lambda c, url, *a: fetched.append(url) or real(c, url, *a))
    got = ingest.changes_since(cfg, 40, floor=T0, stage=lambda p, v: None,
                               release_holds=frozenset({"stale-demo", "flaky-demo"}))
    assert any("/pypi/flaky-demo/" in u for u in fetched)
    assert [r.package for r in got] == ["Stale-Demo", "Beta-Demo"]      # a released hold still emits
    assert got.ceiling == 70
    assert [(n, s) for n, s, _ in got.held] == [("stale-demo", 50), ("flaky-demo", 60)]


def test_a_refused_project_is_reported_and_is_not_held(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)

    def fake_get(cfg_, url, headers, limit, deadline):
        if url.endswith("/simple/"):
            return 200, _hdrs(), _index([(50, "huge-demo"), (60, "beta-demo")], 60)
        if "huge-demo" in url:
            raise fetcher.RefusedToFetch("download-size")
        return 200, _hdrs(X_PyPI_Last_Serial="60"), _pj("Beta-Demo", 60, {"3.0": [("sdist", "2026-09-28T10:07:00Z")]})
    monkeypatch.setattr(ingest, "_get", fake_get)
    got = ingest.changes_since(cfg, 40, floor=T0, stage=lambda p, v: None)
    assert got.refused == [("huge-demo", 50)]
    assert got.held == [] and got.ceiling == 60


def _truncated_index():
    full = json.dumps({"meta": {"_last-serial": 500},
                       "projects": [{"_last-serial": 100 + i, "name": f"p{i}-demo"} for i in range(300)]}).encode()
    return full, full[: len(full) // 2]


def test_a_truncated_uncompressed_index_is_refused(tmp_path, monkeypatch):
    full, cut = _truncated_index()
    assert full.decode().rstrip().endswith("]}")
    with pytest.raises(ValueError):
        ingest._changed(cut.decode(), 0)
    cfg = _cfg(tmp_path)
    monkeypatch.setattr(ingest, "_get", lambda *a: (200, _hdrs(), cut))
    got = ingest.changes_since(cfg, 0, floor=T0, stage=lambda p, v: None)
    assert list(got) == [] and got.ceiling is None


def test_get_refuses_a_body_shorter_than_its_content_length(tmp_path, monkeypatch):
    import http.client
    full, cut = _truncated_index()

    def respond(body, length):
        raw = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n" % length) + body

        class Sock:
            def makefile(self, *a, **k):
                return io.BufferedReader(io.BytesIO(raw))
        r = http.client.HTTPResponse(Sock())
        r.begin()
        return r
    cfg = _cfg(tmp_path)
    monkeypatch.setattr(ingest.urllib.request, "urlopen", lambda req, timeout: respond(cut, len(full)))
    with pytest.raises(ValueError):
        ingest._get(cfg, "https://pypi.invalid/simple/", {}, 10**9, 60)
    monkeypatch.setattr(ingest.urllib.request, "urlopen", lambda req, timeout: respond(full, len(full)))
    assert ingest._get(cfg, "https://pypi.invalid/simple/", {}, 10**9, 60)[2] == full
