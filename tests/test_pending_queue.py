"""LLM review never blocks the scan.

When the reviewer can't handle a flagged release — the endpoint is unreachable, the
flagged content is larger than reviewer.max_input_chars, or review keeps timing out —
the release is parked in a pending-review queue with its reason, and its review input
is stored so a later review doesn't depend on PyPI still hosting the sdist. The
cursor always advances. Each tick drains what it can (unreachable-endpoint parks, and
timeouts with attempts left, at 300s/600s/900s); `review-pending` drains the rest,
e.g. oversized releases with a larger-context model.
"""
import dataclasses
import urllib.error
from pathlib import Path

from pydiffwatch import fetcher, ingest, orchestrator, reviewer, store
from pydiffwatch.config import Config
from pydiffwatch.models import Diff, FileDiff, FiredRule, Hunk, NewRelease, TriageResult

_OK = ('{"classification":"benign","confidence":0.9,"urgent":false,"recommended_action":"monitor",'
       '"attack_type":"none","cited_hunk":"","reasoning":"looked at it"}')


def _cfg(tmp_path, **rv):
    c = dataclasses.replace(Config(), db_path=tmp_path / "db.sqlite", lock_path=tmp_path / "l",
                            cache_dir=tmp_path / "c", rules_dir=Path("rules/community"))
    # The host memory guard reads this machine's real memory; keep these tests independent of it.
    return dataclasses.replace(c, reviewer=dataclasses.replace(c.reviewer, host_memory_guard=False, **rv))


class _Backend:
    primary_model, escalation_model = "m", None

    def __init__(self, fail=None):
        self.fail, self.calls = fail, []

    def complete(self, *, user_text, timeout=None, **kw):
        self.calls.append((user_text, timeout))
        if self.fail is not None:
            raise reviewer.ReviewUnavailable("boom") from self.fail
        return _OK

    def ping(self, text, *, timeout):     # the reviewer guard's probe / calibration: a fast endpoint
        return {"prompt_tokens": 5000, "completion_tokens": 1, "prompt_per_second": 100_000.0}

    def context_length(self, model=None):
        return None


def _setup(tmp_path, backend, **rv):
    cfg = _cfg(tmp_path, **rv)
    conn = store.connect(cfg); store.init_schema(conn)
    rid = store.record_release(conn, "pkg", "1.0.0", 1, False, None, "tgz")
    return cfg, conn, rid, reviewer.Reviewer(cfg, backend=backend)


def _diff(body="exec(x)"):
    return Diff(package="pkg", version="1.0.0", is_first_release=False, added_binaries=[],
                changed=[FileDiff("pkg/a.py", "modified", [Hunk((0, 1), (0, 1), [body], [])])])


_T = TriageResult(score=60.0, escalate=True, fired_rules=[FiredRule("primitives", 60.0, "pkg/a.py", (1, 1))])
_TIMEOUT = TimeoutError("timed out")
_REFUSED = urllib.error.URLError(ConnectionRefusedError(61, "Connection refused"))


def _pending(conn):
    return {r["package"]: r for r in store.pending_reviews(conn)}


def test_oversized_top_file_is_parked_not_sent(tmp_path):
    be = _Backend()
    cfg, conn, rid, rvw = _setup(tmp_path, be, max_input_chars=10_000)
    orchestrator._review_escalated(cfg, conn, rvw, _diff("x" * 50_000), _T, rid)
    assert be.calls == []
    assert store.get_stage(conn, "pkg", "1.0.0") == "pending_review"
    row = _pending(conn)["pkg"]
    assert row["pending_reason"] == "too_large"
    assert "cap 10000" in row["pending_detail"]
    assert "x" * 50_000 in store.review_input(row)           # full input kept for a bigger model


def test_unreachable_endpoint_parks_without_calling_or_spending_attempts(tmp_path):
    be = _Backend()
    cfg, conn, rid, rvw = _setup(tmp_path, be)
    orchestrator._review_escalated(cfg, conn, rvw, _diff(), _T, rid, offline=True)
    assert be.calls == []
    assert _pending(conn)["pkg"]["pending_reason"] == "endpoint_unreachable"
    assert store.review_attempts(conn, rid) == 0


def test_connection_refused_mid_tick_parks_as_unreachable(tmp_path):
    cfg, conn, rid, rvw = _setup(tmp_path, _Backend(fail=_REFUSED))
    orchestrator._review_escalated(cfg, conn, rvw, _diff(), _T, rid)
    assert _pending(conn)["pkg"]["pending_reason"] == "endpoint_unreachable"
    assert store.review_attempts(conn, rid) == 0


def test_drain_reviews_parked_release_with_a_fresh_marker(tmp_path):
    cfg, conn, rid, rvw = _setup(tmp_path, _Backend())
    orchestrator._review_escalated(cfg, conn, rvw, _diff(), _T, rid, offline=True)
    stored = store.review_input(_pending(conn)["pkg"])
    be = _Backend()
    orchestrator.drain_pending(cfg, conn, reviewer.Reviewer(cfg, backend=be), auto=True)
    [(sent, _)] = be.calls
    assert "exec(x)" in sent and sent != stored            # same content, new CSPRNG marker
    assert store.get_stage(conn, "pkg", "1.0.0") == "reviewed"
    assert _pending(conn) == {}


def test_timeouts_retry_at_growing_timeouts_then_stop_auto_retrying(tmp_path):
    be = _Backend(fail=_TIMEOUT)
    cfg, conn, rid, rvw = _setup(tmp_path, be)
    orchestrator._review_escalated(cfg, conn, rvw, _diff(), _T, rid)
    for _ in range(4):
        orchestrator.drain_pending(cfg, conn, rvw, auto=True)
    assert [t for _, t in be.calls] == [300.0, 600.0, 900.0]
    row = _pending(conn)["pkg"]
    assert row["pending_reason"] == "review_failed" and row["review_attempts"] == 3


def test_auto_drain_leaves_too_large_for_manual_review_with_bigger_cap(tmp_path):
    cfg, conn, rid, rvw = _setup(tmp_path, _Backend(), max_input_chars=10_000)
    orchestrator._review_escalated(cfg, conn, rvw, _diff("x" * 50_000), _T, rid)
    be = _Backend()
    orchestrator.drain_pending(cfg, conn, reviewer.Reviewer(cfg, backend=be), auto=True)
    assert be.calls == [] and _pending(conn)["pkg"]["pending_reason"] == "too_large"
    big = _cfg(tmp_path, max_input_chars=800_000)             # e.g. a frontier-model config
    orchestrator.drain_pending(big, conn, reviewer.Reviewer(big, backend=be), auto=False)
    assert len(be.calls) == 1 and _pending(conn) == {}


def test_unreachable_model_does_not_pin_the_cursor(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn); store.set_last_serial(conn, 5000); conn.close()
    rel = NewRelease("pkg", "1.0.0", 5050)
    monkeypatch.setattr(ingest, "changes_since", lambda *a, **k: [rel])
    from types import SimpleNamespace
    art = SimpleNamespace(prior_version="0.9.0", is_new_package=False, maintainer_metadata=None, prior_error=None)
    monkeypatch.setattr(fetcher, "fetch_artifacts", lambda cfg, rel, **k: art)
    monkeypatch.setattr(orchestrator.differ, "build_diff", lambda art: _diff())
    monkeypatch.setattr(orchestrator.engine, "triage", lambda *a, **k: _T)
    monkeypatch.setattr(orchestrator, "_probe_reviewer", lambda cfg: (False, "127.0.0.1:9"))
    orchestrator.run_once(cfg, seed_if_fresh=False)
    conn = store.connect(cfg)
    assert store.get_last_serial(conn) == 5050
    assert _pending(conn)["pkg"]["pending_reason"] == "endpoint_unreachable"


def test_review_pending_command_drains_oversized_with_bigger_model(tmp_path, monkeypatch):
    cfg, conn, rid, rvw = _setup(tmp_path, _Backend(), max_input_chars=10_000)
    orchestrator._review_escalated(cfg, conn, rvw, _diff("x" * 50_000), _T, rid)
    conn.close()
    big = _cfg(tmp_path, max_input_chars=800_000)
    monkeypatch.setattr(orchestrator, "_build_reviewer", lambda cfg: reviewer.Reviewer(cfg, backend=_Backend()))
    reviewed, remaining = orchestrator.review_pending(big)
    assert reviewed == 1 and remaining == {}


def test_drain_limit_counts_attempts_not_successes(tmp_path):
    """Failures must use up the per-tick budget too, or a tick of timeouts runs unbounded (900s each)."""
    be = _Backend(fail=_TIMEOUT)
    cfg, conn, rid, rvw = _setup(tmp_path, be)
    rid2 = store.record_release(conn, "pkg2", "1.0.0", 2, False, None, "tgz")
    orchestrator._review_escalated(cfg, conn, rvw, _diff(), _T, rid)
    orchestrator._review_escalated(cfg, conn, rvw, dataclasses.replace(_diff(), package="pkg2"), _T, rid2)
    be.calls.clear()
    orchestrator.drain_pending(cfg, conn, rvw, auto=True, limit=1)
    assert len(be.calls) == 1


def _adjudicated_too_large(tmp_path, be):
    cfg, conn, rid, rvw = _setup(tmp_path, be, max_input_chars=10_000)
    store.update_evidence(conn, rid, "payload code")
    orchestrator._review_escalated(cfg, conn, rvw, _diff("x" * 50_000), _T, rid)
    store.adjudicate(conn, rid, "malicious", "confirmed by hand")
    big = dataclasses.replace(cfg, reviewer=dataclasses.replace(cfg.reviewer, max_input_chars=200_000))
    return big, conn, rid


def _row(conn, rid):
    return tuple(conn.execute("SELECT r.stage, r.evidence IS NOT NULL, v.classification, v.human_label "
                              "FROM releases r JOIN verdicts v ON v.release_id=r.id WHERE r.id=?", (rid,)).fetchone())


def test_a_row_a_person_adjudicated_is_never_re_reviewed_by_either_drain(tmp_path):
    be = _Backend()
    big, conn, rid = _adjudicated_too_large(tmp_path, be)
    rvw = reviewer.Reviewer(big, backend=be)
    orchestrator.drain_pending(big, conn, rvw, auto=True)               # the cap grew: it fits now
    orchestrator.drain_pending(big, conn, rvw, auto=False)
    assert be.calls == []
    assert _row(conn, rid) == ("pending_review", 1, "suspicious", "malicious")
    assert store.pending_reviews(conn) == [] and store.pending_review_counts(conn) == {}


def test_a_benign_model_verdict_never_drops_the_evidence_of_a_labelled_release(tmp_path):
    cfg, conn, rid, rvw = _setup(tmp_path, _Backend())
    store.update_evidence(conn, rid, "payload code")
    orchestrator._review_escalated(cfg, conn, rvw, _diff(), _T, rid, offline=True)
    store.record_verdict(conn, rid, orchestrator.Verdict("pkg", "1.0.0", "suspicious", 60.0, [], False, model="none"))
    store.adjudicate(conn, rid, "malicious", "confirmed by hand")
    benign = orchestrator.Verdict("pkg", "1.0.0", "benign", 60.0, [], False, model="m", reasoning="fine")
    orchestrator._record(cfg, conn, rid, benign, 60.0)
    assert store.get_evidence(conn, rid) == "payload code"
