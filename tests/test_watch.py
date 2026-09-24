"""watch catches up without sleeping: while a backlog is waiting (a --recent start, or a restart after
downtime) the next tick starts at once, and it sleeps only once caught up. Never really sleeps here."""
from pydiffwatch import ingest, orchestrator, store
from pydiffwatch.config import Config


def _cfg(tmp_path):
    return Config(db_path=tmp_path / "db.sqlite", lock_path=tmp_path / "lock", cache_dir=tmp_path / "cache",
                  reviewer_enabled=False, max_releases_per_run=200)


def _advancing_run(step):
    """A scan tick that moves the cursor `step` serials forward, like a real tick with work to do."""
    def fake_run(c, **k):
        conn = store.connect(c); store.init_schema(conn)
        store.set_last_serial(conn, store.get_last_serial(conn) + step); conn.close()
    return fake_run


def _watch(tmp_path, monkeypatch, step, head, iterations):
    cfg = _cfg(tmp_path)
    monkeypatch.setattr(orchestrator, "run_once", _advancing_run(step))
    monkeypatch.setattr(orchestrator, "export_dashboard", lambda *a, **k: None)
    monkeypatch.setattr(ingest, "current_serial", lambda c: head)
    slept = []
    orchestrator.watch(cfg, interval=300, iterations=iterations, sleep_fn=slept.append)
    return slept


def test_watch_skips_the_sleep_while_a_full_page_is_still_waiting(tmp_path, monkeypatch):
    assert _watch(tmp_path, monkeypatch, step=200, head=100_000, iterations=3) == []


def test_watch_sleeps_once_caught_up(tmp_path, monkeypatch):
    # after tick 1 the cursor is at 200 and only 50 changelog events are left: less than a page
    assert _watch(tmp_path, monkeypatch, step=200, head=250, iterations=2) == [300]


def test_watch_sleeps_when_the_cursor_is_pinned_even_if_behind(tmp_path, monkeypatch):
    # A release that keeps failing to fetch pins the cursor: retrying it back-to-back would hammer PyPI.
    assert _watch(tmp_path, monkeypatch, step=0, head=100_000, iterations=2) == [300]


def test_watch_passes_recent_to_each_tick(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    seen = []
    monkeypatch.setattr(orchestrator, "run_once", lambda c, **k: seen.append(k.get("recent")))
    monkeypatch.setattr(orchestrator, "export_dashboard", lambda *a, **k: None)
    orchestrator.watch(cfg, interval=300, iterations=2, sleep_fn=lambda s: None, recent=500)
    assert seen == [500, 500]


def test_watch_survives_a_locked_database_outside_the_scan(tmp_path, monkeypatch):
    # Final review: _cursor, export_dashboard and _behind sat outside the tick's try/except, so a transient
    # "database is locked" (review-pending writing at the same moment) killed the daemon.
    import sqlite3
    cfg = _cfg(tmp_path)
    runs, slept = [], []
    monkeypatch.setattr(orchestrator, "run_once", lambda c, **k: runs.append(1))
    monkeypatch.setattr(orchestrator, "export_dashboard", lambda *a, **k: None)
    real, calls = orchestrator._cursor, []

    def cursor(c):
        calls.append(1)
        if len(calls) == 1:
            raise sqlite3.OperationalError("database is locked")
        return real(c)
    monkeypatch.setattr(orchestrator, "_cursor", cursor)
    assert orchestrator.watch(cfg, interval=300, iterations=3, sleep_fn=slept.append) == 3
    assert slept == [300, 300] and len(runs) == 2          # the locked tick is skipped, not fatal


def test_watch_survives_a_failed_dashboard_export(tmp_path, monkeypatch):
    import sqlite3
    cfg = _cfg(tmp_path)
    runs, slept, exports = [], [], []
    monkeypatch.setattr(orchestrator, "run_once", lambda c, **k: runs.append(1))

    def export(*a, **k):
        exports.append(1)
        if len(exports) == 1:
            raise sqlite3.OperationalError("database is locked")
    monkeypatch.setattr(orchestrator, "export_dashboard", export)
    assert orchestrator.watch(cfg, interval=300, iterations=2, sleep_fn=slept.append) == 2
    assert len(runs) == 2 and slept == [300]
