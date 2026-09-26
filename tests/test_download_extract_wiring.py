"""C1 wiring (spec §3.1): the fetch pool only downloads; the main thread scans through sandbox.analyze."""
import json, logging

from pydiffwatch import fetcher, orchestrator, sandbox, store
from pydiffwatch.config import Config
from pydiffwatch.models import ArtifactSet, NewRelease


def _cfg(tmp_path, **kw):
    return Config(db_path=tmp_path / "db.sqlite", cache_dir=tmp_path / "c", lock_path=tmp_path / "l",
                  reviewer_enabled=False, **kw)


def _art(**kw):
    base = dict(package="p", version="1.1", prior_version="1.0", basis="sdist",
                new_files={"p/a.py": b"x = 2\n"}, prior_files={"p/a.py": b"x = 1\n"}, artifact_hashes={})
    return ArtifactSet(**{**base, **kw})


def _stage(conn, pkg="p", ver="1.1"):
    return tuple(conn.execute("SELECT stage, fetch_note FROM releases WHERE package=? AND version=?",
                              (pkg, ver)).fetchone())


def _alerts(conn):
    return conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]


def test_fetch_one_only_downloads(monkeypatch):
    monkeypatch.setattr(fetcher, "download", lambda cfg, rel, attempt=1: ("downloaded", attempt))
    monkeypatch.setattr(fetcher, "extract_download", lambda *a: (_ for _ in ()).throw(AssertionError("parsed")))
    assert orchestrator._fetch_one(Config(), NewRelease("p", "1.1", 1), 3) == ("downloaded", 3)


def test_process_fetched_scans_a_download_and_logs_the_time(tmp_path, scan_stub, caplog):
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn)
    caplog.set_level(logging.INFO, logger="pydiffwatch.orchestrator")
    assert orchestrator._process_fetched(cfg, conn, None, orchestrator._load_ruleset(cfg),
                                         NewRelease("p", "1.1", 5), scan_stub.dl(_art())) is True
    assert _stage(conn)[0] == "triaged"
    assert len([r for r in caplog.records if r.getMessage().startswith("scanned p==1.1 in ")]) == 1


def test_the_scans_prior_error_is_the_fetch_note(tmp_path, scan_stub):
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn)
    note = "prior 1.0 sdist unavailable (ReadError: bad); diffed against nothing"
    orchestrator._process_fetched(cfg, conn, None, orchestrator._load_ruleset(cfg), NewRelease("p", "1.1", 5),
                                  scan_stub.dl(_art(prior_files={}, prior_error=note)))
    assert _stage(conn) == ("triaged", note)


def test_a_refusal_wins_over_a_failed_prior_download(tmp_path, scan_stub):
    # Review Focus 1
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn)
    dl = scan_stub.dl(fetcher.RefusedToExtract("members"), "p", "1.1")
    dl = orchestrator.dataclasses.replace(dl, prior_error="prior 1.0 sdist unavailable (TimeoutError: x); "
                                                          "diffed against nothing")
    assert orchestrator._process_fetched(cfg, conn, None, orchestrator._load_ruleset(cfg),
                                         NewRelease("p", "1.1", 5), dl) is True
    assert _stage(conn)[0] == "refused_to_extract" and _alerts(conn) == 1


def test_an_analyze_crash_is_a_retry(tmp_path, scan_stub, monkeypatch):
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn)
    monkeypatch.setattr(sandbox, "analyze", lambda *a, **k: (_ for _ in ()).throw(sandbox.SandboxError("boom")))
    orchestrator._process_fetched(cfg, conn, None, orchestrator._load_ruleset(cfg), NewRelease("p", "1.1", 5),
                                  scan_stub.dl(_art()))
    stage, note = _stage(conn)
    assert stage == "metadata_retry" and "SandboxError: boom" in note


def test_an_analyze_crash_still_records_the_baseline_and_owners(tmp_path, scan_stub, monkeypatch):
    # R2 / plan review C1: the next release's maintainer-set-change reads these
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn)
    monkeypatch.setattr(sandbox, "analyze", lambda *a, **k: (_ for _ in ()).throw(sandbox.SandboxError("boom")))
    orchestrator._process_fetched(cfg, conn, None, orchestrator._load_ruleset(cfg), NewRelease("p", "1.1", 5),
                                  scan_stub.dl(_art(maintainer_metadata={"roles": ["alice"]})))
    row = conn.execute("SELECT stage, prior_version, maintainer_metadata FROM releases").fetchone()
    assert tuple(row) == ("metadata_retry", "1.0", '{"roles": ["alice"]}')


def test_the_retry_sweep_records_a_refusal(tmp_path, scan_stub):
    # Review Focus 3
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn)
    rel = NewRelease("p", "1.1", 5)
    orchestrator._process_fetched(cfg, conn, None, None, rel, TimeoutError("hung"))
    assert _stage(conn)[0] == "metadata_retry"
    conn.execute("UPDATE releases SET recheck_at=0 WHERE package='p'"); conn.commit()   # due now
    scan_stub.fetch(lambda cfg, rel, attempt=1: (_ for _ in ()).throw(fetcher.RefusedToExtract("members")))
    orchestrator._retry_metadata(cfg, conn, None, orchestrator._load_ruleset(cfg), False, None)
    assert _stage(conn)[0] == "refused_to_extract" and _alerts(conn) == 1
    assert store.get_last_serial(conn) == 0          # the sweep never moves the cursor


def test_a_skipped_new_package_clears_an_old_fetch_note(tmp_path, scan_stub):
    # Review Focus 5
    cfg = _cfg(tmp_path, new_package_policy="skip")
    conn = store.connect(cfg); store.init_schema(conn)
    rel = NewRelease("p", "1.0", 5)
    orchestrator._process_fetched(cfg, conn, None, None, rel, TimeoutError("hung"))
    art = _art(version="1.0", prior_version=None, prior_files={}, new_files={}, is_new_package=True)
    orchestrator._process_fetched(cfg, conn, None, orchestrator._load_ruleset(cfg), rel, scan_stub.dl(art))
    assert _stage(conn, "p", "1.0") == ("new_package_skipped", None)


def test_rebuild_of_a_now_refused_release_spends_an_attempt(tmp_path, scan_stub):
    # Review Focus 4: the drain's rebuild maps a refusal to "failed", as before the split
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn)
    rid = store.record_release(conn, "p", "1.1", 5, False, "1.0", "sdist")
    store.update_stage(conn, rid, "pending_review", 50.0, json.dumps([]))
    store.park_for_review(conn, rid, "reviewer_disabled", "reviewer off", "")   # review_input_chars 0: rebuilt
    row = conn.execute("SELECT r.id AS release_id, r.package, r.version, r.serial, r.triage_score, r.triage_rules,"
                       " r.review_attempts, r.pending_reason FROM releases r WHERE r.id=?", (rid,)).fetchone()
    scan_stub.fetch(lambda cfg, rel, attempt=1: (_ for _ in ()).throw(fetcher.RefusedToExtract("members")))
    got = orchestrator._rebuild_review_input(cfg, conn, None, row, orchestrator._load_ruleset(cfg), 10_000)
    assert got == "failed"
    assert conn.execute("SELECT review_attempts FROM releases WHERE id=?", (rid,)).fetchone()[0] == 1


def test_backfill_of_a_first_release_keeps_the_whole_tree_under_surface(tmp_path, scan_stub, monkeypatch):
    # Ruling R1: diffed against nothing, without the surface filter, as before the split
    cfg = _cfg(tmp_path)                      # default new_package_policy = "surface"
    conn = store.connect(cfg); store.init_schema(conn)
    rid = store.record_release(conn, "p", "1.1", 7, True, None, "sdist")
    store.update_stage(conn, rid, "reviewed", 75.0, json.dumps(
        [{"rule": "combo-decode-exec", "weight": 45.0, "file": "p/deep/x.py", "lines": [1, 2]}]))
    payload = b"import base64\nexec(base64.b64decode('eA=='))\n"
    art = _art(new_files={"p/deep/x.py": payload}, prior_files={"p/deep/x.py": payload})
    seen = {}
    real = sandbox.analyze

    def spy(cfg_, dl, owners, ruleset, backend=None):
        seen["dl"] = dl
        return real(cfg_, dl, owners, ruleset, backend)
    monkeypatch.setattr(sandbox, "analyze", spy)
    scan_stub.fetch(lambda cfg, rel: art)
    orchestrator.backfill_evidence(cfg, rid, all_flagged=True)
    assert seen["dl"].prior_version is None and seen["dl"].is_new_package is False


def test_a_corrupt_new_sdist_records_the_baseline_and_owners(tmp_path):
    # R2 (Task 6 review): before the split this failed in the fetch thread and recorded neither; now analyze fails
    # and the crash branch records what the download established
    from pydiffwatch.models import Download
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn)
    dl = Download("p", "1.1", "1.0", False, b"not a gzip", None, None, {"roles": ["alice"]}, [], None, None)
    orchestrator._process_fetched(cfg, conn, None, orchestrator._load_ruleset(cfg), NewRelease("p", "1.1", 5), dl)
    row = conn.execute("SELECT stage, prior_version, maintainer_metadata, fetch_note FROM releases").fetchone()
    assert tuple(row)[:3] == ("metadata_retry", "1.0", '{"roles": ["alice"]}')
    assert "BadGzipFile" in row[3]
