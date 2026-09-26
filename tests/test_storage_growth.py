"""The scan database must not grow without bound (port of npmDiffWatch #16). Evidence is stored compressed and
only where a person may act; plain release rows older than `retention_days` are pruned, daily, by run/watch.
PyPI adaptation: retention keeps each package's newest release that carries maintainer metadata, because
get_release_metadata reads it as the next release's maintainer baseline."""
import dataclasses
import datetime
import json

from pydiffwatch import ingest, orchestrator, store
from pydiffwatch.config import Config, load_config
from pydiffwatch.models import ArtifactSet, FiredRule, NewRelease, TriageResult, Verdict

_EV = "--- file: setup.py (modified) ---\n" + "+ some flagged code line\n" * 2000


def _db(tmp_path, **over):
    cfg = dataclasses.replace(Config(), db_path=tmp_path / "db.sqlite", lock_path=tmp_path / "lock",
                              cache_dir=tmp_path / "cache", reviewer_enabled=False, **over)
    conn = store.connect(cfg); store.init_schema(conn)
    return cfg, conn


def _raw(conn, rid):
    return conn.execute("SELECT evidence FROM releases WHERE id=?", (rid,)).fetchone()[0]


def _verdict(pkg, cls):
    return Verdict(pkg, "1.0", cls, 60.0, [], False, confidence=0.9, attack_type="none", reasoning="r",
                   cited_hunk="", model="m")


def test_evidence_is_stored_compressed_and_read_back_as_text(tmp_path):
    _, conn = _db(tmp_path)
    rid = store.record_release(conn, "p", "1.0", 1, False, None, "sdist")
    store.update_evidence(conn, rid, _EV)
    assert isinstance(_raw(conn, rid), bytes) and len(_raw(conn, rid)) < len(_EV) / 4
    assert store.get_evidence(conn, rid) == _EV


def test_evidence_written_as_plain_text_by_older_versions_still_reads(tmp_path):
    cfg, conn = _db(tmp_path)
    rid = store.record_release(conn, "p", "1.0", 1, False, None, "sdist")
    conn.execute("UPDATE releases SET evidence=? WHERE id=?", (_EV, rid)); conn.commit()
    assert store.get_evidence(conn, rid) == _EV
    assert orchestrator.get_evidence(cfg, rid) == _EV                     # the `evidence` CLI path


def test_pending_shows_compressed_evidence_as_text(tmp_path):
    cfg, conn = _db(tmp_path)
    rid = store.record_release(conn, "p", "1.0", 1, False, None, "sdist")
    store.update_evidence(conn, rid, _EV)
    store.record_verdict(conn, rid, _verdict("p", "suspicious"))
    store.update_stage(conn, rid, "needs_adjudication")
    [item] = orchestrator.list_pending(cfg)
    assert item["diff_text"] == _EV and item["evidence_stored"] is True


def test_a_benign_verdict_drops_the_evidence_and_a_flagged_one_keeps_it(tmp_path):
    cfg, conn = _db(tmp_path)
    ids = {}
    for cls in ("benign", "suspicious", "malicious"):
        ids[cls] = store.record_release(conn, cls, "1.0", 1, False, None, "sdist")
        store.update_evidence(conn, ids[cls], _EV)
        orchestrator._record(cfg, conn, ids[cls], _verdict(cls, cls), 60.0)
    assert store.get_evidence(conn, ids["benign"]) is None
    assert store.get_evidence(conn, ids["suspicious"]) == _EV == store.get_evidence(conn, ids["malicious"])


def _old(conn, pkg, ver, days, stage="triaged", evidence=None, metadata=None):
    rid = store.record_release(conn, pkg, ver, 1, False, None, "sdist")
    when = (datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=days)).isoformat()
    conn.execute("UPDATE releases SET processed_at=?, stage=?, evidence=?, maintainer_metadata=? WHERE id=?",
                 (when, stage, evidence, json.dumps(metadata) if metadata else None, rid))
    conn.commit()
    return rid


def test_prune_compresses_legacy_evidence_and_drops_what_nobody_needs(tmp_path):
    _, conn = _db(tmp_path)
    flagged = _old(conn, "bad", "1.0", 1, stage="needs_adjudication", evidence=_EV)
    store.record_verdict(conn, flagged, _verdict("bad", "suspicious"))
    below = _old(conn, "quiet", "1.0", 1, stage="triaged", evidence=_EV)          # never escalated
    cleared = _old(conn, "fine", "1.0", 1, stage="reviewed", evidence=_EV)
    store.record_verdict(conn, cleared, _verdict("fine", "benign"))
    alerted = _old(conn, "heur", "1.0", 1, stage="alerted", evidence=_EV)         # heuristic alert, no reviewer
    store.prune(conn, retention_days=90)
    assert isinstance(_raw(conn, flagged), bytes) and store.get_evidence(conn, flagged) == _EV
    assert store.get_evidence(conn, alerted) == _EV
    assert _raw(conn, below) is None and _raw(conn, cleared) is None


def test_prune_keeps_evidence_for_a_partial_review_benign_verdict_awaiting_adjudication(tmp_path):
    # spec U2: a benign verdict on truncated input is routed to needs_adjudication, not saved silently
    # — a person may still act on it, so prune must not wipe its evidence (and must not keep re-picking
    # it up via releases_needing_evidence on every capture-evidence -> prune cycle).
    _, conn = _db(tmp_path)
    partial = _old(conn, "part", "1.0", 1, stage="needs_adjudication", evidence=_EV)
    store.record_verdict(conn, partial, _verdict("part", "benign"))
    store.prune(conn, retention_days=90)
    assert store.get_evidence(conn, partial) == _EV


def test_retention_keeps_findings_queues_and_the_newest_release_of_each_package(tmp_path):
    _, conn = _db(tmp_path)
    old_plain = _old(conn, "lib", "1.0", 120)
    newest = _old(conn, "lib", "1.1", 120)                        # still the newest of its package
    recent = _old(conn, "other", "1.0", 10)
    old_other = _old(conn, "other", "0.9", 120)
    kept = {newest, recent}
    for stage in ("pending_review", "needs_adjudication", "metadata_retry", "gave_up",
                  "refused_to_extract", "refused_to_fetch"):
        kept.add(_old(conn, stage, "1.0", 120, stage=stage))       # a person may still act on these
        _old(conn, stage, "1.1", 1)
    refused = _old(conn, "unreviewed", "1.0", 120, stage="refused_to_extract")
    store.record_verdict(conn, refused, _verdict("unreviewed", "suspicious"))
    flagged = _old(conn, "bad", "1.0", 120, stage="reviewed")
    store.record_verdict(conn, flagged, _verdict("bad", "malicious"))
    gone = _old(conn, "gone", "1.0", 120, stage="metadata_gone")
    store.record_alert(conn, gone, "suspicious-heuristic", 0.0, "[]", "gone==1.0")
    for pkg in ("unreviewed", "bad", "gone"):
        _old(conn, pkg, "1.1", 1)
    store.prune(conn, retention_days=90)
    left = {r[0] for r in conn.execute("SELECT id FROM releases")}
    assert old_plain not in left and old_other not in left
    assert kept | {refused, flagged, gone} <= left


def test_retention_keeps_the_maintainer_baseline_behind_a_newer_release_without_metadata(tmp_path):
    # 2.0 carries the maintainer metadata; 2.1 was wheel-only (no_sdist, no metadata). PyPI's predecessor
    # of the next sdist release is 2.0, so get_release_metadata must still find it after a prune.
    _, conn = _db(tmp_path)
    meta = {"author": "alice", "maintainer": None, "roles": ["alice"], "upload_time": "2026-01-01T00:00:00Z"}
    _old(conn, "lib", "1.9", 200, metadata={**meta, "roles": ["old"]})
    _old(conn, "lib", "2.0", 150, metadata=meta)
    _old(conn, "lib", "2.1", 120, stage="no_sdist")
    store.prune(conn, retention_days=90)
    assert store.get_release_metadata(conn, "lib", "2.0") == meta
    assert store.get_release_metadata(conn, "lib", "1.9") is None                 # older baseline pruned


def test_retention_zero_keeps_everything(tmp_path):
    _, conn = _db(tmp_path)
    old = _old(conn, "lib", "1.0", 400)
    _old(conn, "lib", "1.1", 1)
    store.prune(conn, retention_days=0)
    assert conn.execute("SELECT count(*) FROM releases WHERE id=?", (old,)).fetchone()[0] == 1


def test_prune_runs_by_itself_at_most_once_a_day(tmp_path):
    _, conn = _db(tmp_path)
    t0 = 1_000_000.0
    assert store.maybe_prune(conn, retention_days=90, every_s=86_400, now=t0) is True
    assert store.maybe_prune(conn, retention_days=90, every_s=86_400, now=t0 + 3_600) is False
    assert store.maybe_prune(conn, retention_days=90, every_s=86_400, now=t0 + 86_401) is True


def test_config_defaults_and_toml(tmp_path):
    assert Config().retention_days == 90 and Config().prune_every_hours == 24.0
    p = tmp_path / "c.toml"
    p.write_text("retention_days = 0\nprune_every_hours = 6.0\n")
    cfg = load_config(p)
    assert (cfg.retention_days, cfg.prune_every_hours) == (0, 6.0)


def test_a_release_below_the_review_threshold_stores_no_evidence(tmp_path, monkeypatch, scan_stub):
    from pydiffwatch import differ, reviewer, sandbox
    cfg, conn = _db(tmp_path)
    art = ArtifactSet("quiet", "1.1", "1.0", "sdist", {"setup.py": b"exec(x)\n"}, {"setup.py": b"x\n"}, {},
                      added_binaries=[], is_new_package=False, maintainer_metadata=None, added_dep_findings=[])
    monkeypatch.setattr(sandbox, "analyze",
                        lambda cfg, dl, owners, ruleset, backend=None: (differ.build_diff(art),
                        TriageResult(10.0, [FiredRule("exec", 10.0, "setup.py", (1, 1))], False), None))
    monkeypatch.setattr(reviewer, "build_evidence", lambda *a, **k: _EV)
    orchestrator._process_fetched(cfg, conn, None, orchestrator._load_ruleset(cfg), NewRelease("quiet", "1.1", 5),
                                  scan_stub.dl(art))
    assert conn.execute("SELECT evidence FROM releases WHERE package='quiet'").fetchone()[0] is None


def test_run_prunes_by_itself_at_most_once_per_interval(tmp_path, monkeypatch):
    cfg, conn = _db(tmp_path)
    store.set_last_serial(conn, 100)
    monkeypatch.setattr(ingest, "changes_since", lambda c, last: [])
    old = _old(conn, "lib", "1.0", 120); _old(conn, "lib", "1.1", 1)
    orchestrator.run_once(cfg)
    assert conn.execute("SELECT count(*) FROM releases WHERE id=?", (old,)).fetchone()[0] == 0
    again = _old(conn, "lib", "0.9", 120)
    orchestrator.run_once(cfg)                                    # same day: no second prune
    assert conn.execute("SELECT count(*) FROM releases WHERE id=?", (again,)).fetchone()[0] == 1
    # a day later (the last prune's time is kept in the database, so cron-driven `run` counts too)
    last = float(conn.execute("SELECT value FROM meta WHERE key='last_prune'").fetchone()[0])
    conn.execute("UPDATE meta SET value=? WHERE key='last_prune'", (str(last - 86_401),)); conn.commit()
    orchestrator.run_once(cfg)
    assert conn.execute("SELECT count(*) FROM releases WHERE id=?", (again,)).fetchone()[0] == 0


def test_prune_command_shrinks_an_existing_database(tmp_path):
    cfg, conn = _db(tmp_path)
    for i in range(20):
        _old(conn, f"p{i}", "1.0", 1, stage="triaged", evidence=_EV)               # legacy plain text
    conn.close()
    before = cfg.db_path.stat().st_size
    freed = orchestrator.prune(cfg)
    assert freed > 0 and cfg.db_path.stat().st_size < before


def test_prune_drops_unneeded_evidence_before_compressing_and_compresses_in_batches(tmp_path, monkeypatch):
    # Final review: the first prune on a legacy DB fetchall()ed every plain-text evidence row into memory and
    # compressed it, including rows it was about to NULL.
    _, conn = _db(tmp_path)
    kept = [_old(conn, f"bad{i}", "1.0", 1, stage="needs_adjudication", evidence=_EV) for i in range(1203)]
    dropped = _old(conn, "fine", "1.0", 1, stage="triaged", evidence=_EV)
    compressed, sql = [], []
    real = store.zlib.compress
    monkeypatch.setattr(store.zlib, "compress", lambda b: compressed.append(b) or real(b))
    conn.set_trace_callback(sql.append)
    store.prune(conn)
    conn.set_trace_callback(None)
    assert len(compressed) == len(kept)                          # the triaged row was dropped, never compressed
    assert _raw(conn, dropped) is None
    assert all(store.get_evidence(conn, rid) == _EV for rid in kept)
    selects = [s for s in sql if s.lstrip().upper().startswith("SELECT") and "typeof(evidence)" in s]
    assert len(selects) >= 3 and all("LIMIT" in s for s in selects)
