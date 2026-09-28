import datetime
import pytest

from pydiffwatch import ingest, orchestrator, store
from pydiffwatch.config import Config
from pydiffwatch.models import NewRelease


def _cfg(tmp_path):
    return Config(db_path=tmp_path / "d.db", lock_path=tmp_path / "state" / "l.lock", reviewer_enabled=False)


def _stub_tick(monkeypatch, changes):
    monkeypatch.setattr(orchestrator.egress, "is_installed", lambda: True)
    monkeypatch.setattr(orchestrator.sandbox, "choose", lambda cfg: None)
    monkeypatch.setattr(orchestrator, "_load_ruleset", lambda cfg: None)
    monkeypatch.setattr(orchestrator, "_fetch_one", lambda cfg, rel, *a: None)
    monkeypatch.setattr(orchestrator, "_process_fetched", lambda *a: True)
    seen = {}

    def fake(cfg, since, **kw):
        seen.update(kw, since=since)
        return changes
    monkeypatch.setattr(ingest, "changes_since", fake)
    return seen


def test_the_cursor_jumps_to_the_ceiling_when_nothing_is_listed(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn); store.set_last_serial(conn, 100)
    ch = ingest.Changes(); ch.ceiling = 180
    _stub_tick(monkeypatch, ch)
    orchestrator.run_once(cfg)
    assert store.get_last_serial(store.connect(cfg)) == 180


def test_the_cursor_never_passes_the_ceiling(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn); store.set_last_serial(conn, 100)
    ch = ingest.Changes([NewRelease("alpha-demo", "1.0", 150), NewRelease("beta-demo", "2.0", 170)])
    ch.ceiling = 159
    _stub_tick(monkeypatch, ch)
    orchestrator.run_once(cfg)
    assert store.get_last_serial(store.connect(cfg)) == 159


def test_the_floor_is_passed_and_advances_after_a_full_tick(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn); store.set_last_serial(conn, 100)
    store.set_meta(conn, "ingest_floor", "2026-01-01T00:00:00+00:00")
    ch = ingest.Changes(); ch.ceiling = 120
    ch.complete = True
    seen = _stub_tick(monkeypatch, ch)
    orchestrator.run_once(cfg)
    assert seen["floor"] == "2026-01-01T00:00:00+00:00" and callable(seen["stage"])
    new_floor = store.get_meta(store.connect(cfg), "ingest_floor")
    expect = datetime.datetime.now(datetime.UTC) - datetime.timedelta(minutes=cfg.floor_margin_minutes)
    assert abs(datetime.datetime.fromisoformat(new_floor) - expect) < datetime.timedelta(minutes=1)


def test_the_floor_does_not_move_when_the_poll_was_incomplete(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn); store.set_last_serial(conn, 100)
    store.set_meta(conn, "ingest_floor", "2026-01-01T00:00:00+00:00")
    ch = ingest.Changes(); ch.ceiling = 120
    ch.complete = False
    _stub_tick(monkeypatch, ch)
    orchestrator.run_once(cfg)
    assert store.get_meta(store.connect(cfg), "ingest_floor") == "2026-01-01T00:00:00+00:00"
    assert store.get_last_serial(store.connect(cfg)) == 120


def test_the_floor_does_not_move_when_the_cursor_is_held(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn); store.set_last_serial(conn, 100)
    store.set_meta(conn, "ingest_floor", "2026-01-01T00:00:00+00:00")
    ch = ingest.Changes([NewRelease("alpha-demo", "1.0", 150)]); ch.ceiling = 150
    ch.complete = True
    _stub_tick(monkeypatch, ch)
    monkeypatch.setattr(orchestrator, "_process_fetched", lambda *a: False)   # not terminal: cursor blocked
    orchestrator.run_once(cfg)
    assert store.get_meta(store.connect(cfg), "ingest_floor") == "2026-01-01T00:00:00+00:00"


def test_a_plain_list_stub_keeps_the_old_advance(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn); store.set_last_serial(conn, 100)
    _stub_tick(monkeypatch, [NewRelease("alpha-demo", "1.0", 130)])
    orchestrator.run_once(cfg)
    assert store.get_last_serial(store.connect(cfg)) == 130


def test_a_naive_or_malformed_stored_floor_does_not_crash_the_tick(tmp_path, monkeypatch):
    for bad_floor in ("2026-01-01T00:00:00", "garbage"):
        cfg = _cfg(tmp_path / bad_floor.replace(":", "_"))
        conn = store.connect(cfg); store.init_schema(conn); store.set_last_serial(conn, 100)
        store.set_meta(conn, "ingest_floor", bad_floor)
        ch = ingest.Changes(); ch.ceiling = 120
        ch.complete = True
        _stub_tick(monkeypatch, ch)
        orchestrator.run_once(cfg)          # must not raise
        assert store.get_last_serial(store.connect(cfg)) == 120
        new_floor = store.get_meta(store.connect(cfg), "ingest_floor")
        got = datetime.datetime.fromisoformat(new_floor)
        assert got.tzinfo is not None
        expect = datetime.datetime.now(datetime.UTC) - datetime.timedelta(minutes=cfg.floor_margin_minutes)
        assert abs(got - expect) < datetime.timedelta(minutes=1)


def test_the_cursor_never_reaches_a_serial_whose_releases_are_not_all_terminal(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn); store.set_last_serial(conn, 100)
    ch = ingest.Changes([NewRelease("a-demo", "1.0", 150), NewRelease("a-demo", "1.1", 150)])
    ch.ceiling = 150
    _stub_tick(monkeypatch, ch)

    def fetched(cfg, conn, rvw, ruleset, rel, result, offline, guard):
        return rel.version == "1.0"
    monkeypatch.setattr(orchestrator, "_process_fetched", fetched)
    orchestrator.run_once(cfg)
    assert store.get_last_serial(store.connect(cfg)) == 149


def test_an_index_failure_leaves_the_cursor_and_floor_unchanged(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn); store.set_last_serial(conn, 100)
    store.set_meta(conn, "ingest_floor", "2026-01-01T00:00:00+00:00")
    ch = ingest.Changes(); ch.ceiling = None
    _stub_tick(monkeypatch, ch)
    orchestrator.run_once(cfg)
    assert store.get_last_serial(store.connect(cfg)) == 100
    assert store.get_meta(store.connect(cfg), "ingest_floor") == "2026-01-01T00:00:00+00:00"


# ---- final fix pass: C1 floor for upgraded DBs, C2 interrupted releases, I1 bounded holds, P1 refused alert ----
import dataclasses
import email.message
import io
import json
import urllib.error


def _hdrs(**kv):
    m = email.message.Message()
    for k, v in kv.items():
        m[k] = v
    return m


def _stub_pipeline(monkeypatch):
    monkeypatch.setattr(orchestrator.egress, "is_installed", lambda: True)
    monkeypatch.setattr(orchestrator.sandbox, "choose", lambda cfg: None)
    monkeypatch.setattr(orchestrator, "_load_ruleset", lambda cfg: None)
    monkeypatch.setattr(orchestrator, "_fetch_one", lambda cfg, rel, *a: None)


def _project_json(name, versions):
    return json.dumps({"info": {"name": name},
                       "releases": {v: [{"packagetype": "sdist", "upload_time_iso_8601": ts}] for v, ts in versions.items()}}).encode()


def _serve(monkeypatch, projects, fail=()):
    """projects: {name: (index serial, {version: upload iso})}; names in `fail` answer 503."""
    fetched = []

    def fake_get(cfg_, url, headers, limit, deadline):
        if url.endswith("/simple/"):
            return 200, _hdrs(), json.dumps({"meta": {"_last-serial": max(s for s, _ in projects.values())},
                                             "projects": [{"_last-serial": s, "name": n}
                                                          for n, (s, _) in projects.items()]}).encode()
        name = url.split("/pypi/")[1].split("/")[0]
        fetched.append(name)
        if name in fail:
            raise urllib.error.HTTPError(url, 503, "backend timeout", _hdrs(), io.BytesIO(b""))
        s, versions = projects[name]
        return 200, _hdrs(**{"X-PyPI-Last-Serial": str(s)}), _project_json(name, versions)
    monkeypatch.setattr(ingest, "_get", fake_get)
    return fetched


def _now_iso(**delta):
    return (datetime.datetime.now(datetime.UTC) - datetime.timedelta(**delta)).isoformat()


def test_an_upgraded_database_gets_a_floor_and_does_not_flood(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn); store.set_last_serial(conn, 41_500_000)
    old = datetime.datetime(2019, 1, 1, tzinfo=datetime.UTC)
    versions = {f"0.{i}": (old + datetime.timedelta(days=i)).isoformat() for i in range(400)}
    versions["0.400"] = _now_iso()
    _stub_pipeline(monkeypatch)
    _serve(monkeypatch, {"bigold-demo": (41_556_000, versions)})
    processed = []
    monkeypatch.setattr(orchestrator, "_process_fetched", lambda cfg, conn, rvw, rs, rel, *a: processed.append(rel) or True)
    orchestrator.run_once(cfg)
    assert [(r.package, r.version) for r in processed] == [("bigold-demo", "0.400")]
    assert store.get_meta(store.connect(cfg), "ingest_floor") is not None


def test_the_seeded_floor_trails_the_cursors_last_update(tmp_path, monkeypatch):
    for updated_at, back in ((_now_iso(days=3), datetime.timedelta(days=3)), ("garbage", datetime.timedelta(0)),
                             (None, datetime.timedelta(0))):
        cfg = _cfg(tmp_path / str(abs(hash(str(updated_at)))))
        conn = store.connect(cfg); store.init_schema(conn); store.set_last_serial(conn, 100)
        conn.execute("UPDATE cursor SET updated_at=? WHERE id=1", (updated_at,)); conn.commit()
        ch = ingest.Changes(); ch.ceiling = 100
        seen = _stub_tick(monkeypatch, ch)
        orchestrator.run_once(cfg)
        expect = datetime.datetime.now(datetime.UTC) - back - datetime.timedelta(minutes=cfg.floor_margin_minutes)
        assert abs(datetime.datetime.fromisoformat(seen["floor"]) - expect) < datetime.timedelta(minutes=1)


def test_a_backfill_leaves_the_floor_unset_across_ticks(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn)
    ch = ingest.Changes(); ch.ceiling = 120          # an incomplete poll: the floor does not move forward
    seen = _stub_tick(monkeypatch, ch)
    orchestrator.run_once(cfg, seed_if_fresh=False)
    assert seen["floor"] is None and store.get_last_serial(store.connect(cfg)) == 120
    orchestrator.run_once(cfg, seed_if_fresh=False)
    assert seen["floor"] is None
    assert store.get_meta(store.connect(cfg), "ingest_floor") is None


def test_a_release_interrupted_mid_scan_is_fetched_again(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn); store.set_last_serial(conn, 100)
    store.set_meta(conn, "ingest_floor", _now_iso(hours=1))
    _stub_pipeline(monkeypatch)
    _serve(monkeypatch, {"alpha-demo": (150, {"1.0": _now_iso()}), "zeta-demo": (200, {})})

    def killed(cfg, conn, rvw, ruleset, rel, result, *a):
        store.record_release(conn, rel.package, rel.version, rel.serial, False, None, "sdist")
        raise KeyboardInterrupt("killed mid-scan")
    monkeypatch.setattr(orchestrator, "_process_fetched", killed)
    with pytest.raises(KeyboardInterrupt):
        orchestrator.run_once(cfg)
    assert store.get_stage(store.connect(cfg), "alpha-demo", "1.0") == "ingested"

    processed = []
    monkeypatch.setattr(orchestrator, "_process_fetched",
                        lambda cfg, conn, rvw, rs, rel, *a: processed.append(rel.version) or False)
    orchestrator.run_once(cfg)                      # fetched again, still not terminal: the cursor stays below it
    assert processed == ["1.0"] and store.get_last_serial(store.connect(cfg)) < 150
    monkeypatch.setattr(orchestrator, "_process_fetched",
                        lambda cfg, conn, rvw, rs, rel, *a: processed.append(rel.version) or True)
    orchestrator.run_once(cfg)
    assert processed == ["1.0", "1.0"] and store.get_last_serial(store.connect(cfg)) == 200


def _unscanned_alerts(cfg, name):
    return store.connect(cfg).execute("SELECT dedupe_key FROM alerts WHERE dedupe_key LIKE ?",
                                      (f"{name}|%",)).fetchall()


def test_a_project_that_always_fails_is_released_after_max_hold_ticks(tmp_path, monkeypatch):
    cfg = dataclasses.replace(_cfg(tmp_path), max_projects_per_run=3, max_hold_ticks=3)
    conn = store.connect(cfg); store.init_schema(conn); store.set_last_serial(conn, 100)
    store.set_meta(conn, "ingest_floor", _now_iso(hours=1))
    _stub_pipeline(monkeypatch)
    monkeypatch.setattr(orchestrator, "_process_fetched", lambda *a: True)
    projects = {"stuck-demo": (101, {"1.0": _now_iso()})}
    fetched = _serve(monkeypatch, projects, fail={"stuck-demo"})
    for tick in range(1, 7):
        projects[f"new{tick}-demo"] = (200 + tick, {"1.0": _now_iso()})
        fetched.clear()
        orchestrator.run_once(cfg)
    assert store.get_last_serial(store.connect(cfg)) == 206
    assert "new6-demo" in fetched and "stuck-demo" not in fetched
    assert len(_unscanned_alerts(cfg, "stuck-demo")) == 1
    c = store.connect(cfg)
    assert store.get_stage(c, "stuck-demo", "*") == "gave_up"
    row = [r for r in store.pending_adjudication(c) if r["package"] == "stuck-demo"]
    assert len(row) == 1 and row[0]["model"] == "none" and row[0]["classification"] == "suspicious"
    assert row[0]["reasoning"].startswith("UNREVIEWED:") and "stuck-demo" in row[0]["reasoning"]
    assert row[0]["reasoning"].endswith("Not scanned. Needs manual review.")
    assert json.loads(store.get_meta(c, "ingest_holds") or "{}") == {}


def test_a_hold_that_clears_before_the_limit_raises_no_alert(tmp_path, monkeypatch):
    cfg = dataclasses.replace(_cfg(tmp_path), max_hold_ticks=3)
    conn = store.connect(cfg); store.init_schema(conn); store.set_last_serial(conn, 100)
    store.set_meta(conn, "ingest_floor", _now_iso(hours=1))
    _stub_pipeline(monkeypatch)
    monkeypatch.setattr(orchestrator, "_process_fetched", lambda *a: True)
    fail = {"flaky-demo"}
    _serve(monkeypatch, {"flaky-demo": (150, {"1.0": _now_iso()}), "beta-demo": (200, {})}, fail=fail)
    for _ in range(2):
        orchestrator.run_once(cfg)
    assert store.get_last_serial(store.connect(cfg)) == 149
    assert json.loads(store.get_meta(store.connect(cfg), "ingest_holds")) == {"flaky-demo": {"serial": 150, "ticks": 2}}
    fail.clear()
    orchestrator.run_once(cfg)
    assert store.get_last_serial(store.connect(cfg)) == 200
    assert _unscanned_alerts(cfg, "flaky-demo") == []
    assert json.loads(store.get_meta(store.connect(cfg), "ingest_holds")) == {}


def test_a_project_over_the_size_cap_alerts_and_does_not_hold(tmp_path, monkeypatch):
    from pydiffwatch import fetcher
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn); store.set_last_serial(conn, 100)
    store.set_meta(conn, "ingest_floor", _now_iso(hours=1))
    _stub_pipeline(monkeypatch)
    monkeypatch.setattr(orchestrator, "_process_fetched", lambda *a: True)
    _serve(monkeypatch, {"huge-demo": (150, {}), "beta-demo": (200, {})})
    real = ingest._get

    def refuse(cfg_, url, *a):
        if "/pypi/huge-demo/" in url:
            raise fetcher.RefusedToFetch("download-size")
        return real(cfg_, url, *a)
    monkeypatch.setattr(ingest, "_get", refuse)
    orchestrator.run_once(cfg)
    orchestrator.run_once(cfg)
    c = store.connect(cfg)
    assert store.get_last_serial(c) == 200
    assert store.get_stage(c, "huge-demo", "*") == "refused_to_fetch"
    assert len(_unscanned_alerts(cfg, "huge-demo")) == 1
    row = [r for r in store.pending_adjudication(c) if r["package"] == "huge-demo"]
    assert len(row) == 1 and row[0]["reasoning"].startswith("UNREVIEWED:")
    assert "huge-demo" in row[0]["reasoning"] and row[0]["reasoning"].endswith("Not scanned. Needs manual review.")


def test_the_project_level_row_is_never_downloaded_by_pending_or_retries(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn)
    for stage in ("refused_to_fetch", "gave_up"):
        name = f"{stage}-demo"
        rid = store.record_release(conn, name, "*", 150, False, None, "sdist")
        store.update_stage(conn, rid, stage)
        orchestrator._alert_unscanned(cfg, conn, rid, name, "*", "UNREVIEWED: x. Not scanned. Needs manual review.",
                                      stage=stage)
    monkeypatch.setattr(orchestrator.sandbox, "choose", lambda cfg: None)
    monkeypatch.setattr(orchestrator, "_load_ruleset", lambda cfg: None)

    def no_download(*a, **k):
        raise AssertionError("tried to download version *")
    monkeypatch.setattr(orchestrator, "_scan_release", no_download)
    monkeypatch.setattr(orchestrator, "_fetch_one", no_download)
    items = orchestrator.list_pending(cfg)
    assert sorted(i["package"] for i in items) == ["gave_up-demo", "refused_to_fetch-demo"]
    assert store.metadata_retries_due(conn) == []
    assert not orchestrator._to_fetch(conn, NewRelease("gave_up-demo", "*", 150))
    orchestrator.prune(cfg)
    store.prune(store.connect(cfg), retention_days=1)
    assert len(store.pending_adjudication(store.connect(cfg))) == 2
