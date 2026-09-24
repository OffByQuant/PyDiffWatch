"""Every outcome that leaves a release unscanned warns once (spec U1, U3). The alert's reasoning starts
`UNREVIEWED:`; the release waits in `pending`, which names the stage it stopped at instead of a model label;
and a later tick never repeats the alert. `metadata_gone` also alerts, but stays out of `pending`: the files
are gone, so nobody can review it."""
import dataclasses
import sys

from pydiffwatch import __main__ as cli
from pydiffwatch import fetcher, ingest, orchestrator, reviewer, store
from pydiffwatch.models import NewRelease
from tests.test_pending_queue import _Backend, _T, _TIMEOUT, _diff, _setup


def _alerts(conn, package):
    return conn.execute("SELECT a.dedupe_key FROM alerts a JOIN releases r ON r.id = a.release_id "
                        "WHERE r.package=? ORDER BY a.id", (package,)).fetchall()


def _pending_cli(cfg, monkeypatch, capsys):
    """`pydiffwatch pending` with every entry-point side effect stubbed: no network, no scan, no refetch."""
    cfg = dataclasses.replace(cfg, reviewer_enabled=False)
    monkeypatch.setattr(cli, "_cfg", lambda args: cfg)
    monkeypatch.setattr(cli.egress, "install_guard", lambda cfg: None)
    monkeypatch.setattr(cli, "run_once", lambda *a, **k: (_ for _ in ()).throw(AssertionError("scanned")))
    monkeypatch.setattr(cli, "watch", lambda *a, **k: (_ for _ in ()).throw(AssertionError("watched")))
    monkeypatch.setattr(ingest, "changes_since", lambda *a, **k: (_ for _ in ()).throw(AssertionError("ingest")))
    monkeypatch.setattr(ingest, "current_serial", lambda *a, **k: (_ for _ in ()).throw(AssertionError("ingest")))
    monkeypatch.setattr(fetcher, "fetch_artifacts", lambda *a, **k: (_ for _ in ()).throw(AssertionError("refetched")))
    monkeypatch.setattr(sys, "argv", ["pydiffwatch", "pending"])
    capsys.readouterr()
    cli.main()
    return capsys.readouterr().out


def _unreviewed(text):
    return "UNREVIEWED:" in text and "Not scanned. Needs manual review." in text


# --- gave_up -------------------------------------------------------------------------------------------

def test_gave_up_warns_once_with_the_last_error_and_waits_in_pending(tmp_cfg, capsys, monkeypatch):
    conn = store.connect(tmp_cfg); store.init_schema(conn)
    rel = NewRelease("flaky", "1.0", 10)
    for i in range(store.METADATA_ATTEMPTS - 1):
        orchestrator._process_fetched(tmp_cfg, conn, None, None, rel, TimeoutError(f"hung {i}"))
    assert capsys.readouterr().out == "" and _alerts(conn, "flaky") == []
    orchestrator._process_fetched(tmp_cfg, conn, None, None, rel, fetcher.MetadataUnavailable("HTTP 503"))
    out = capsys.readouterr().out
    assert store.get_stage(conn, "flaky", "1.0") == "gave_up"
    assert "flaky 1.0" in out and _unreviewed(out)
    assert "4 times" in out and "MetadataUnavailable: HTTP 503" in out
    orchestrator._process_fetched(tmp_cfg, conn, None, None, rel, TimeoutError("again"))   # a re-tick
    assert capsys.readouterr().out == "" and len(_alerts(conn, "flaky")) == 1
    [item] = orchestrator.list_pending(tmp_cfg)
    assert item["package"] == "flaky" and "HTTP 503" in item["reasoning"] and item["diff_text"] is None
    out = _pending_cli(tmp_cfg, monkeypatch, capsys)
    assert "(not scanned: gave_up)" in out and "model: suspicious" not in out


# --- quarantined refused_to_fetch ----------------------------------------------------------------------

def test_a_quarantined_package_alerts_without_calling_it_malicious(tmp_cfg, capsys, monkeypatch):
    conn = store.connect(tmp_cfg); store.init_schema(conn)
    rel = NewRelease("cudrequest", "0.2.0", 7)
    orchestrator._process_fetched(tmp_cfg, conn, None, None, rel, fetcher.RefusedToFetch("quarantined: cudrequest"))
    out = capsys.readouterr().out
    assert "cudrequest 0.2.0" in out and "quarantine list" in out and _unreviewed(out)
    assert "typosquat of `requests`" in out                     # the quarantine reason
    assert "[DIFFWATCH] malicious" not in out
    orchestrator._process_fetched(tmp_cfg, conn, None, None, rel, fetcher.RefusedToFetch("quarantined: cudrequest"))
    assert capsys.readouterr().out == "" and len(_alerts(conn, "cudrequest")) == 1
    [item] = orchestrator.list_pending(tmp_cfg)
    assert item["classification"] != "malicious" and "quarantine list" in item["reasoning"]
    out = _pending_cli(tmp_cfg, monkeypatch, capsys)
    assert "(not scanned: refused_to_fetch)" in out and "model: suspicious" not in out


# --- too_large -----------------------------------------------------------------------------------------

def test_too_large_alerts_once_with_the_needed_size_and_the_cap(tmp_path, capsys, monkeypatch):
    cfg, conn, rid, rvw = _setup(tmp_path, _Backend(), max_input_chars=10_000)
    orchestrator._review_escalated(cfg, conn, rvw, _diff("x" * 50_000), _T, rid)
    out = capsys.readouterr().out
    needed = store.pending_reviews(conn)[0]["pending_detail"].split()[1]
    assert "pkg 1.0.0" in out and _unreviewed(out) and "score=60" in out
    assert f"needs {needed} chars" in out and "cap 10000" in out
    assert "run `review-pending` with a larger-context model" in out
    assert len(_alerts(conn, "pkg")) == 1                        # still one alert, not heuristic + unscanned
    for _ in range(2):                                           # re-ticks: the auto-drain leaves it parked
        orchestrator.drain_pending(cfg, conn, reviewer.Reviewer(cfg, backend=_Backend()), auto=True)
    assert capsys.readouterr().out == "" and len(_alerts(conn, "pkg")) == 1
    [item] = orchestrator.list_pending(cfg)
    assert item["package"] == "pkg" and "larger-context model" in item["reasoning"]
    out = _pending_cli(cfg, monkeypatch, capsys)
    assert "(not scanned: too_large)" in out and "model: suspicious" not in out


def test_a_too_large_release_that_is_later_reviewed_leaves_pending(tmp_path, capsys):
    cfg, conn, rid, rvw = _setup(tmp_path, _Backend(), max_input_chars=10_000)
    orchestrator._review_escalated(cfg, conn, rvw, _diff("x" * 50_000), _T, rid)
    big = dataclasses.replace(cfg, reviewer=dataclasses.replace(cfg.reviewer, max_input_chars=800_000))
    orchestrator.drain_pending(big, conn, reviewer.Reviewer(big, backend=_Backend()), auto=False)
    assert store.get_stage(conn, "pkg", "1.0.0") == "reviewed" and orchestrator.list_pending(cfg) == []


# --- review_failed, retries exhausted ------------------------------------------------------------------

def test_exhausted_review_retries_warn_once_after_the_first_park_alert(tmp_path, capsys, monkeypatch):
    be = _Backend(fail=_TIMEOUT)
    cfg, conn, rid, rvw = _setup(tmp_path, be)
    orchestrator._review_escalated(cfg, conn, rvw, _diff(), _T, rid)
    first = capsys.readouterr().out
    assert "suspicious-heuristic" in first and "UNREVIEWED" not in first      # first park: heuristic alert
    orchestrator.drain_pending(cfg, conn, rvw, auto=True)                     # attempt 2
    assert capsys.readouterr().out == ""
    orchestrator.drain_pending(cfg, conn, rvw, auto=True)                     # attempt 3: exhausted
    out = capsys.readouterr().out
    assert "pkg 1.0.0" in out and _unreviewed(out) and "3 times" in out
    for _ in range(2):                                                        # re-ticks: skipped, no alert
        orchestrator.drain_pending(cfg, conn, rvw, auto=True)
    assert capsys.readouterr().out == "" and len(be.calls) == 3
    assert len(_alerts(conn, "pkg")) == 2                                     # first park + exhaustion
    [item] = orchestrator.list_pending(cfg)
    assert "3 times" in item["reasoning"]
    out = _pending_cli(cfg, monkeypatch, capsys)
    assert "(not scanned: review_failed)" in out and "model: suspicious" not in out


# --- metadata_gone -------------------------------------------------------------------------------------

def test_metadata_gone_alerts_once_and_stays_out_of_pending(tmp_cfg, capsys, monkeypatch):
    conn = store.connect(tmp_cfg); store.init_schema(conn)
    rel = NewRelease("gone", "1.0", 3)
    orchestrator._process_fetched(tmp_cfg, conn, None, None, rel, fetcher.MetadataGone("404"))
    out = capsys.readouterr().out
    assert "gone 1.0" in out and "removed from PyPI before it could be scanned" in out
    assert "the files are gone, so there is nothing to review" in out
    orchestrator._process_fetched(tmp_cfg, conn, None, None, rel, fetcher.MetadataGone("404"))
    assert capsys.readouterr().out == "" and len(_alerts(conn, "gone")) == 1
    assert orchestrator.list_pending(tmp_cfg) == []
    assert "not scanned" not in _pending_cli(tmp_cfg, monkeypatch, capsys)


# --- refused_to_extract keeps its wording, gains the stage label ---------------------------------------

def test_refused_extract_shows_its_stage_in_pending(tmp_cfg, capsys, monkeypatch):
    conn = store.connect(tmp_cfg); store.init_schema(conn)
    orchestrator._process_fetched(tmp_cfg, conn, None, None, NewRelease("big", "1.0", 1),
                                  fetcher.RefusedToExtract("members"))
    out = _pending_cli(tmp_cfg, monkeypatch, capsys)
    assert "(not scanned: refused_to_extract)" in out and "model: suspicious" not in out


def test_the_dashboard_renders_an_unscanned_release(tmp_cfg, capsys):
    conn = store.connect(tmp_cfg); store.init_schema(conn)
    orchestrator._process_fetched(tmp_cfg, conn, None, None, NewRelease("cudrequest", "0.2.0", 7),
                                  fetcher.RefusedToFetch("quarantined: cudrequest"))
    html = orchestrator.export_dashboard(tmp_cfg).read_text()
    assert "cudrequest" in html and "UNREVIEWED:" in html


def test_prune_keeps_every_unscanned_row(tmp_path, capsys):
    cfg, conn, rid, rvw = _setup(tmp_path, _Backend(), max_input_chars=10_000)
    orchestrator._review_escalated(cfg, conn, rvw, _diff("x" * 50_000), _T, rid)                 # too_large
    rid2 = store.record_release(conn, "pkg2", "1.0.0", 2, False, None, "tgz")
    rvw2 = reviewer.Reviewer(cfg, backend=_Backend(fail=_TIMEOUT))
    orchestrator._review_escalated(cfg, conn, rvw2, dataclasses.replace(_diff(), package="pkg2"), _T, rid2)
    for _ in range(2):
        orchestrator.drain_pending(cfg, conn, rvw2, auto=True)                                    # exhausted
    for i in range(store.METADATA_ATTEMPTS):
        orchestrator._process_fetched(cfg, conn, None, None, NewRelease("flaky", "1.0", 10), TimeoutError(str(i)))
    orchestrator._process_fetched(cfg, conn, None, None, NewRelease("cudrequest", "0.2.0", 11),
                                  fetcher.RefusedToFetch("quarantined: cudrequest"))
    orchestrator._process_fetched(cfg, conn, None, None, NewRelease("gone", "1.0", 12), fetcher.MetadataGone("404"))
    for pkg in ("pkg", "pkg2", "flaky", "cudrequest", "gone"):      # a newer release, so none is its package's newest
        store.record_release(conn, pkg, "9.9", 99, False, None, "sdist")
    conn.execute("UPDATE releases SET processed_at='2000-01-01T00:00:00+00:00' WHERE version != '9.9'")
    conn.commit()
    store.prune(conn, retention_days=1)
    kept = {r[0] for r in conn.execute("SELECT package FROM releases WHERE version != '9.9'")}
    assert kept == {"pkg", "pkg2", "flaky", "cudrequest", "gone"}
