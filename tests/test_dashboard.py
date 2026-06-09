from pydiffwatch import dashboard, store, orchestrator
from pydiffwatch.config import Config
from pydiffwatch.models import Verdict


# ---- pure-function tests (no DB) ----
def test_pypi_version_url():
    assert dashboard.pypi_version_url("requests", "2.31.0") == \
        "https://pypi.org/project/requests/2.31.0/"


def test_render_includes_version_url():
    out = dashboard.render_dashboard([{"package": "evilpkg", "version": "1.0.0",
                                       "classification": "malicious"}])
    assert "https://pypi.org/project/evilpkg/1.0.0/" in out


def test_render_flagged_has_report_link():
    out = dashboard.render_dashboard([{"package": "evilpkg", "version": "1.0.0",
                                       "classification": "malicious"}])
    assert "Report malware on PyPI" in out
    assert "https://pypi.org/project/evilpkg/" in out


def test_render_benign_has_no_report_link():
    out = dashboard.render_dashboard([{"package": "okpkg", "version": "2.0.0",
                                       "classification": "benign"}])
    assert "Report malware on PyPI" not in out
    assert "https://pypi.org/project/okpkg/2.0.0/" in out


def test_render_escapes_untrusted_package_name():
    out = dashboard.render_dashboard([{"package": "<script>alert(1)</script>",
                                       "version": "1.0.0", "classification": "malicious"}])
    assert "<script>alert(1)" not in out
    assert "&lt;script&gt;" in out


def test_render_orders_flagged_first():
    out = dashboard.render_dashboard([
        {"package": "benignpkg", "version": "1.0.0", "classification": "benign"},
        {"package": "malpkg", "version": "1.0.0", "classification": "malicious"},
    ])
    assert out.index("malpkg") < out.index("benignpkg")


# ---- DB-backed test ----
def _cfg(tmp_path):
    # reviewer_enabled=False -> export_dashboard's reviewer probe returns early without any socket
    # call, keeping these tests off the network and independent of process-wide socket state.
    return Config(db_path=tmp_path / "diffwatch.sqlite", reviewer_enabled=False)


def test_watch_refreshes_dashboard_each_tick_and_is_bounded(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    # don't hit PyPI: stub the scan so watch() only exercises its loop + dashboard refresh
    ticks = {"n": 0}
    monkeypatch.setattr(orchestrator, "run_once", lambda c: ticks.__setitem__("n", ticks["n"] + 1))
    sleeps = []
    n = orchestrator.watch(cfg, interval=42, iterations=3, sleep_fn=sleeps.append)
    assert n == 3
    assert ticks["n"] == 3
    assert sleeps == [42, 42]  # sleeps between ticks, not after the last
    assert (cfg.db_path.parent / "dashboard.html").exists()


def test_watch_survives_a_failing_scan(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    def boom(c):
        raise RuntimeError("scan exploded")
    monkeypatch.setattr(orchestrator, "run_once", boom)
    n = orchestrator.watch(cfg, iterations=2, sleep_fn=lambda _: None)
    assert n == 2  # daemon stayed up despite the scan failures
    assert (cfg.db_path.parent / "dashboard.html").exists()


def test_export_dashboard_writes_file(tmp_path):
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn)
    rid = store.record_release(conn, "evilpkg", "1.0.0", 1, False, "0.9.0", "diff")
    store.record_verdict(conn, rid, Verdict(
        package="evilpkg", version="1.0.0", classification="malicious",
        score=99.0, fired_rules=[], urgent=True,
        confidence=1.0, attack_type="install-hook-rce",
        reasoning="exfiltrates env", cited_hunk="setup.py:3", model="gemma-4-12b-it"))
    conn.close()
    out = orchestrator.export_dashboard(cfg)
    assert out.exists()
    assert "evilpkg" in out.read_text()
