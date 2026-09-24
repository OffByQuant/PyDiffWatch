"""Every outcome that leaves a release unscanned warns once (spec U1, U3). The alert's reasoning starts
`UNREVIEWED:`; the release waits in `pending`, which names the stage it stopped at instead of a model label;
and a later tick never repeats the alert. `metadata_gone` also alerts, but stays out of `pending`: the files
are gone, so nobody can review it."""
import dataclasses
import json
import sqlite3
import sys

import pytest

from pydiffwatch import __main__ as cli
from pydiffwatch import differ, engine, fetcher, ingest, orchestrator, reviewer, store
from pydiffwatch import guard as guard_mod
from pydiffwatch.models import ArtifactSet, NewRelease
from tests.test_pending_queue import _Backend, _REFUSED, _T, _TIMEOUT, _diff, _setup


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


# --- migration -----------------------------------------------------------------------------------------

_OLD_SCHEMA = """
CREATE TABLE cursor(id INTEGER PRIMARY KEY CHECK(id=1), last_serial INTEGER NOT NULL DEFAULT 0, updated_at TEXT);
INSERT INTO cursor(id, last_serial) VALUES (1, 0);
CREATE TABLE releases(id INTEGER PRIMARY KEY, package TEXT, version TEXT, serial INTEGER, is_first_release INTEGER,
  prior_version TEXT, artifact_basis TEXT, triage_score REAL, triage_rules TEXT, stage TEXT, processed_at TEXT,
  UNIQUE(package, version));
CREATE TABLE alerts(id INTEGER PRIMARY KEY, release_id INTEGER, classification TEXT, score REAL, fired_rules TEXT,
  dedupe_key TEXT UNIQUE, delivery_status TEXT, sent_at TEXT);
CREATE TABLE verdicts(id INTEGER PRIMARY KEY, release_id INTEGER UNIQUE, classification TEXT, confidence REAL,
  attack_type TEXT, reasoning TEXT, cited_hunk TEXT, model TEXT, urgent INTEGER, created_at TEXT,
  human_label TEXT, human_note TEXT, adjudicated_at TEXT);
INSERT INTO releases(id, package, version, serial, stage) VALUES
  (1, 'old-extract', '1.0', 1, 'refused_to_extract'),
  (2, 'old-fetch', '1.0', 2, 'refused_to_fetch'),
  (3, 'has-verdict', '1.0', 3, 'refused_to_extract'),
  (4, 'fine', '1.0', 4, 'triaged');
INSERT INTO verdicts(release_id, classification, reasoning, model, human_label)
  VALUES (3, 'suspicious', 'kept as is', 'none', 'benign');
"""


def test_old_verdictless_refusals_get_the_unreviewed_verdict_once(tmp_cfg, monkeypatch, capsys):
    raw = sqlite3.connect(tmp_cfg.db_path); raw.executescript(_OLD_SCHEMA); raw.commit(); raw.close()
    for _ in range(2):                                            # idempotent across connects
        conn = store.connect(tmp_cfg); store.init_schema(conn)
        rows = conn.execute("SELECT release_id, classification, model, reasoning, human_label FROM verdicts "
                            "ORDER BY release_id").fetchall()
        conn.close()
        assert [r["release_id"] for r in rows] == [1, 2, 3]
        assert all(r["classification"] == "suspicious" and r["model"] == "none" for r in rows)
        assert _unreviewed(rows[0]["reasoning"]) and _unreviewed(rows[1]["reasoning"])
        assert rows[2]["reasoning"] == "kept as is" and rows[2]["human_label"] == "benign"
    assert [i["package"] for i in orchestrator.list_pending(tmp_cfg)] == ["old-extract", "old-fetch"]
    out = _pending_cli(tmp_cfg, monkeypatch, capsys)
    assert "(not scanned: refused_to_extract)" in out and "(not scanned: refused_to_fetch)" in out


# --- Task 8: the review queue ---------------------------------------------------------------------------

def _big(cfg, **rv):
    return dataclasses.replace(cfg, reviewer=dataclasses.replace(cfg.reviewer, **rv))


@pytest.mark.parametrize("fail, reason", [(_TIMEOUT, "review_failed"), (_REFUSED, "endpoint_unreachable")])
def test_a_row_back_on_an_auto_retried_reason_drops_its_stale_unreviewed_verdict(tmp_path, capsys, fail, reason):
    # (a): too_large waits in `pending`; once a bigger cap lets the auto-drain try it and the try fails with an
    # auto-retried reason, the auto-drain owns it again, so the stale "too large" verdict must go.
    cfg, conn, rid, rvw = _setup(tmp_path, _Backend(), max_input_chars=10_000)
    orchestrator._review_escalated(cfg, conn, rvw, _diff("x" * 50_000), _T, rid)
    assert [i["not_scanned"] for i in orchestrator.list_pending(cfg)] == ["too_large"]
    big = _big(cfg, max_input_chars=800_000)
    orchestrator.drain_pending(big, conn, reviewer.Reviewer(big, backend=_Backend(fail=fail)), auto=True)
    assert store.pending_reviews(conn)[0]["pending_reason"] == reason
    assert orchestrator.list_pending(cfg) == []


def _parked(conn, rid, text, reason="endpoint_unreachable"):
    store.update_stage(conn, rid, "triaged", _T.score, json.dumps([r.__dict__ for r in _T.fired_rules]))
    store.park_for_review(conn, rid, reason, "down", text)


def test_a_cold_start_re_park_as_too_large_is_silent_until_the_cap_is_measured(tmp_path, capsys):
    # (b): the 40,000-char cold-start cap is provisional. Re-parking over it must not claim the release needs a
    # manual review; once the endpoint is measured and the row is still over the real cap, it warns, once.
    be = _Backend()
    cfg, conn, rid, rvw = _setup(tmp_path, be)
    _parked(conn, rid, "x" * 60_000)
    gd = guard_mod.ReviewerGuard(cfg, be, conn, memory=None, out=lambda m: None)
    assert gd.tok_s is None and gd.input_cap_chars() == guard_mod.COLD_START_CAP
    orchestrator.drain_pending(cfg, conn, rvw, auto=True, guard=gd)
    assert store.pending_reviews(conn)[0]["pending_reason"] == "too_large"
    assert capsys.readouterr().out == "" and _alerts(conn, "pkg") == []
    gd.tok_s = 50.0                                          # measured: cap ~30,600 chars, still under 60,000
    for _ in range(2):
        orchestrator.drain_pending(cfg, conn, rvw, auto=True, guard=gd)
    out = capsys.readouterr().out
    assert _unreviewed(out) and "too large" in out and len(_alerts(conn, "pkg")) == 1
    assert [i["not_scanned"] for i in orchestrator.list_pending(cfg)] == ["too_large"] and be.calls == []


def test_lowering_max_review_attempts_still_warns_once(tmp_path, capsys):
    # (c): 2 failed attempts under max 5, then the config drops to 2. The row is now exhausted; it must warn.
    be = _Backend(fail=_TIMEOUT)
    cfg, conn, rid, rvw = _setup(tmp_path, be, max_review_attempts=5)
    orchestrator._review_escalated(cfg, conn, rvw, _diff(), _T, rid)
    orchestrator.drain_pending(cfg, conn, rvw, auto=True)
    capsys.readouterr()
    low = _big(cfg, max_review_attempts=2)
    for _ in range(2):
        orchestrator.drain_pending(low, conn, rvw, auto=True)
    out = capsys.readouterr().out
    assert _unreviewed(out) and "2 times" in out and "boom" in out
    assert len(be.calls) == 2 and len(_alerts(conn, "pkg")) == 2               # first park + exhaustion, once
    assert [i["not_scanned"] for i in orchestrator.list_pending(cfg)] == ["review_failed"]


def _escalating(monkeypatch):
    monkeypatch.setattr(differ, "build_diff", lambda art: _diff())
    monkeypatch.setattr(engine, "triage", lambda *a, **k: _T)
    return ArtifactSet("pkg", "1.0.0", "0.9", "sdist", {}, {}, {})


def test_a_late_review_exception_parks_the_release_and_later_exhausts(tmp_path, capsys, monkeypatch):
    # D20: the download and scan succeeded, so an exception in the review must not refetch the release. It is
    # parked as a failed review attempt; the auto-drain retries it and the exhaustion alert still fires.
    be = _Backend(fail=_TIMEOUT)
    cfg, conn, rid, rvw = _setup(tmp_path, be)
    art = _escalating(monkeypatch)
    real = rvw.review_text
    monkeypatch.setattr(rvw, "review_text", lambda *a, **k: (_ for _ in ()).throw(KeyError("confidence")))
    assert orchestrator._process_fetched(cfg, conn, rvw, None, NewRelease("pkg", "1.0.0", 1), art)
    row = conn.execute("SELECT stage, pending_reason, review_attempts, fetch_attempts FROM releases").fetchone()
    assert tuple(row) == ("pending_review", "review_failed", 1, 0)
    assert "suspicious-heuristic" in capsys.readouterr().out                  # the first-park alert
    for _ in range(3):                                                         # exceptions and timeouts alike
        orchestrator.drain_pending(cfg, conn, rvw, auto=True)
        monkeypatch.setattr(rvw, "review_text", real)
    out = capsys.readouterr().out
    assert _unreviewed(out) and "3 times" in out and len(_alerts(conn, "pkg")) == 2
    assert store.get_stage(conn, "pkg", "1.0.0") == "pending_review" and len(be.calls) == 1


def test_an_exception_while_preparing_the_review_parks_instead_of_refetching(tmp_path, capsys, monkeypatch):
    # D20, outside the model call: the parked row carries a review input the auto-drain can re-drive.
    cfg, conn, rid, rvw = _setup(tmp_path, _Backend())
    art = _escalating(monkeypatch)
    monkeypatch.setattr(rvw, "prepare", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("prepare broke")))
    assert orchestrator._process_fetched(cfg, conn, rvw, None, NewRelease("pkg", "1.0.0", 1), art)
    [row] = store.pending_reviews(conn)
    assert (row["pending_reason"], row["review_attempts"]) == ("review_failed", 1)
    assert "RuntimeError: prepare broke" in row["pending_detail"] and "exec(x)" in store.review_input(row)
    assert store.fetch_attempts(conn, rid) == 0
    orchestrator.drain_pending(cfg, conn, rvw, auto=True)
    assert store.get_stage(conn, "pkg", "1.0.0") == "reviewed"


# --- Task 8, fix round 1 --------------------------------------------------------------------------------

def _boom(*a, **k):
    raise ValueError("deterministic bug on this diff")


@pytest.mark.parametrize("target", ["build_review_input", "build_evidence"])
def test_a_failure_after_triage_still_gives_up_with_its_alert(tmp_path, capsys, monkeypatch, target):
    # Review finding 1: the failure count was reset right after triage, before the evidence and review steps
    # (both parse attacker-controlled diff content), so a deterministic crash there retried forever, silently.
    cfg, conn, rid, rvw = _setup(tmp_path, _Backend())
    art = _escalating(monkeypatch)
    monkeypatch.setattr(reviewer, target, _boom)
    rel = NewRelease("pkg", "1.0.0", 1)
    seen = []
    for _ in range(store.METADATA_ATTEMPTS + 2):
        orchestrator._process_fetched(cfg, conn, rvw, None, rel, art)
        seen.append((store.get_stage(conn, "pkg", "1.0.0"), store.fetch_attempts(conn, rid)))
    assert seen[store.METADATA_ATTEMPTS - 1] == ("gave_up", store.METADATA_ATTEMPTS), seen
    out = capsys.readouterr().out
    assert _unreviewed(out) and "gave up" in out and "deterministic bug" in out
    assert [k for (k,) in _alerts(conn, "pkg")] == ["pkg|1.0.0|suspicious-heuristic|unscanned:gave_up"]
