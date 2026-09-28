"""Cursor seeding (§3.3): by default a fresh cursor starts monitoring from NOW (PyPI's current
serial), not from genesis. `seed-now` does it explicitly; `--backfill` (seed_if_fresh=False) opts out
to process from the cursor as-is. All hermetic — ingest is mocked, no live PyPI call."""
import logging
from pydiffwatch import egress, ingest, orchestrator, store


def _throw(*a, **k):
    raise AssertionError("must not be called")


def test_run_once_warns_when_egress_guard_not_installed(tmp_cfg, monkeypatch, caplog):
    # Library callers reach run_once without the CLI entry point's install_guard(); surface that the
    # in-process egress guard is absent rather than failing silently. The CLI path never trips this.
    monkeypatch.setattr(ingest, "current_serial", lambda cfg: 5000)
    monkeypatch.setattr(ingest, "changes_since", _throw)
    assert not egress.is_installed()
    with caplog.at_level(logging.WARNING, logger="pydiffwatch.orchestrator"):
        orchestrator.run_once(tmp_cfg)
    assert any("egress guard" in r.message.lower() for r in caplog.records)


def test_fresh_cursor_seeds_to_now_and_processes_nothing(tmp_cfg, monkeypatch):
    monkeypatch.setattr(ingest, "current_serial", lambda cfg: 5000)
    monkeypatch.setattr(ingest, "changes_since", _throw)   # must NOT crawl history
    n = orchestrator.run_once(tmp_cfg)
    assert n == 0
    conn = store.connect(tmp_cfg)
    assert store.get_last_serial(conn) == 5000             # cursor jumped to 'now'
    conn.close()


def test_fresh_cursor_seed_failure_skips_run(tmp_cfg, monkeypatch):
    monkeypatch.setattr(ingest, "current_serial", lambda cfg: None)   # PyPI unreachable
    monkeypatch.setattr(ingest, "changes_since", _throw)
    assert orchestrator.run_once(tmp_cfg) == 0
    conn = store.connect(tmp_cfg)
    assert store.get_last_serial(conn) == 0                # unchanged; retried next tick
    conn.close()


def test_backfill_does_not_seed_and_processes_from_genesis(tmp_cfg, monkeypatch):
    monkeypatch.setattr(ingest, "current_serial", _throw)             # must NOT seed under backfill
    seen = {}
    monkeypatch.setattr(ingest, "changes_since", lambda cfg, since, **kw: (seen.update(since=since) or []))
    assert orchestrator.run_once(tmp_cfg, seed_if_fresh=False) == 0
    assert seen["since"] == 0                              # processed from the cursor as-is (genesis)


def test_established_cursor_polls_forward_without_reseeding(tmp_cfg, monkeypatch):
    conn = store.connect(tmp_cfg); store.init_schema(conn); store.set_last_serial(conn, 700); conn.close()
    monkeypatch.setattr(ingest, "current_serial", _throw)             # must NOT reseed an established cursor
    seen = {}
    monkeypatch.setattr(ingest, "changes_since", lambda cfg, since, **kw: (seen.update(since=since) or []))
    orchestrator.run_once(tmp_cfg)
    assert seen["since"] == 700                            # polled forward from the existing cursor


def test_seed_now_sets_cursor_to_current_serial(tmp_cfg, monkeypatch):
    monkeypatch.setattr(ingest, "current_serial", lambda cfg: 9999)
    assert orchestrator.seed_now(tmp_cfg) == 9999
    conn = store.connect(tmp_cfg)
    assert store.get_last_serial(conn) == 9999
    conn.close()


def test_seed_now_returns_none_when_pypi_unreachable(tmp_cfg, monkeypatch):
    monkeypatch.setattr(ingest, "current_serial", lambda cfg: None)
    assert orchestrator.seed_now(tmp_cfg) is None
    conn = store.connect(tmp_cfg)
    assert store.get_last_serial(conn) == 0                # left unseeded
    conn.close()


def test_recent_starts_a_fresh_cursor_n_events_back_and_scans_in_the_same_tick(tmp_cfg, monkeypatch, scan_stub):
    from pydiffwatch.models import NewRelease
    monkeypatch.setattr(ingest, "current_serial", lambda cfg: 10_000)
    seen = []
    monkeypatch.setattr(ingest, "changes_since",
                        lambda cfg, since, **kw: seen.append(since) or [NewRelease("pkg", "1.0", 9_700)])
    scan_stub.fetch(lambda cfg, rel: None)   # no sdist: terminal
    assert orchestrator.run_once(tmp_cfg, recent=500) == 1
    assert seen == [9_500]
    conn = store.connect(tmp_cfg)
    assert store.get_last_serial(conn) == 9_700
    conn.close()


def test_recent_is_ignored_once_the_cursor_is_set(tmp_cfg, monkeypatch):
    conn = store.connect(tmp_cfg); store.init_schema(conn); store.set_last_serial(conn, 5000); conn.close()
    monkeypatch.setattr(ingest, "current_serial", lambda cfg: 10_000)
    seen = []
    monkeypatch.setattr(ingest, "changes_since", lambda cfg, since, **kw: seen.append(since) or [])
    orchestrator.run_once(tmp_cfg, recent=500)
    assert seen == [5000]


def test_seeding_sets_the_new_version_floor_to_now(tmp_path, monkeypatch):
    import datetime
    from pydiffwatch import ingest, orchestrator, store
    from pydiffwatch.config import Config
    cfg = Config(db_path=tmp_path / "d.db", lock_path=tmp_path / "l.lock")
    monkeypatch.setattr(ingest, "current_serial", lambda cfg: 5000)
    assert orchestrator.seed_now(cfg) == 5000
    floor = datetime.datetime.fromisoformat(store.get_meta(store.connect(cfg), "ingest_floor"))
    assert abs(floor - datetime.datetime.now(datetime.UTC)) < datetime.timedelta(minutes=1)


def test_recent_starts_n_serials_back_with_a_day_of_floor(tmp_path, monkeypatch):
    import datetime
    from pydiffwatch import ingest, orchestrator, store
    from pydiffwatch.config import Config
    cfg = Config(db_path=tmp_path / "d.db", lock_path=tmp_path / "state" / "l.lock", reviewer_enabled=False)
    monkeypatch.setattr(orchestrator.egress, "is_installed", lambda: True)
    monkeypatch.setattr(orchestrator.sandbox, "choose", lambda cfg: None)
    monkeypatch.setattr(orchestrator, "_load_ruleset", lambda cfg: None)
    monkeypatch.setattr(ingest, "current_serial", lambda cfg: 5000)
    seen = {}

    def fake(cfg_, since, **kw):
        seen.update(kw, since=since)
        return ingest.Changes()
    monkeypatch.setattr(ingest, "changes_since", fake)
    orchestrator.run_once(cfg, recent=500)
    assert seen["since"] == 4500
    floor = datetime.datetime.fromisoformat(seen["floor"])
    expect = datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=cfg.recent_floor_hours)
    assert abs(floor - expect) < datetime.timedelta(minutes=1)
