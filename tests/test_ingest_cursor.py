import datetime

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
