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
    monkeypatch.setattr(ingest, "changes_since", lambda cfg, since: (seen.update(since=since) or []))
    assert orchestrator.run_once(tmp_cfg, seed_if_fresh=False) == 0
    assert seen["since"] == 0                              # processed from the cursor as-is (genesis)


def test_established_cursor_polls_forward_without_reseeding(tmp_cfg, monkeypatch):
    conn = store.connect(tmp_cfg); store.init_schema(conn); store.set_last_serial(conn, 700); conn.close()
    monkeypatch.setattr(ingest, "current_serial", _throw)             # must NOT reseed an established cursor
    seen = {}
    monkeypatch.setattr(ingest, "changes_since", lambda cfg, since: (seen.update(since=since) or []))
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
