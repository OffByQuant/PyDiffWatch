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
