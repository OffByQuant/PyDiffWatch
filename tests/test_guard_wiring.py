# tests/test_guard_wiring.py
"""The orchestrator asks the guard before every review and reports every outcome."""
import dataclasses
from pathlib import Path
from types import SimpleNamespace

from pydiffwatch import fetcher, guard as g, ingest, orchestrator, reviewer, store
from pydiffwatch.config import Config
from pydiffwatch.models import Diff, FileDiff, FiredRule, Hunk, NewRelease, TriageResult

_OK = ('{"classification":"benign","confidence":0.9,"urgent":false,"recommended_action":"monitor",'
       '"attack_type":"none","cited_hunk":"","reasoning":"r"}')


class Backend:
    primary_model, escalation_model = "m", None

    def __init__(self, hang=False, usage=None, ping_ok=True):
        self.hang, self.usage, self.ping_ok, self.calls, self.pings = hang, usage, ping_ok, 0, 0
        self.last_usage = None

    def complete(self, **kw):
        self.calls += 1
        if self.hang:
            raise reviewer.ReviewUnavailable("could not reach reviewer endpoint (timed out)") from TimeoutError("timed out")
        self.last_usage = self.usage
        return _OK

    def ping(self, text, *, timeout):
        self.pings += 1
        if not self.ping_ok:
            raise reviewer.ReviewUnavailable("still busy") from TimeoutError("timed out")
        return {"prompt_tokens": 1000, "completion_tokens": 1}

    def context_length(self, model=None):
        return None


def _cfg(tmp_path, **rv):
    c = dataclasses.replace(Config(), db_path=tmp_path / "db.sqlite", lock_path=tmp_path / "l",
                            cache_dir=tmp_path / "c", rules_dir=Path("rules/community"))
    return dataclasses.replace(c, reviewer=dataclasses.replace(c.reviewer, host_memory_guard=False, **rv))


def _diff(pkg, body="eval(x)"):
    return Diff(package=pkg, version="1.0.0", is_first_release=False, added_binaries=[],
                changed=[FileDiff("a.js", "modified", [Hunk((0, 1), (0, 1), [body], [])])])


_T = TriageResult(score=60.0, escalate=True, fired_rules=[FiredRule("js-eval", 60.0, "a.js", (1, 1))])


def _setup(tmp_path, be, **rv):
    cfg = _cfg(tmp_path, **rv)
    conn = store.connect(cfg); store.init_schema(conn)
    gd = g.ReviewerGuard(cfg, be, conn, memory=None, out=lambda m: None)
    gd.tok_s = 1000.0
    return cfg, conn, gd, reviewer.Reviewer(cfg, backend=be)


def _reasons(conn):
    return {r["package"]: r["pending_reason"] for r in store.pending_reviews(conn)}


def test_timeout_parks_the_rest_of_the_batch_as_model_busy(tmp_path):
    be = Backend(hang=True)
    cfg, conn, gd, rvw = _setup(tmp_path, be)
    for i, pkg in enumerate(["a", "b", "c"]):
        rid = store.record_release(conn, pkg, "1.0.0", i, False, None, "tgz")
        orchestrator._review_escalated(cfg, conn, rvw, _diff(pkg), _T, rid, guard=gd)
    assert be.calls == 1                                           # only the first one reached the model
    assert _reasons(conn) == {"a": "review_failed", "b": "model_busy", "c": "model_busy"}
    assert store.review_attempts(conn, 2) == 0                     # model_busy spends no attempt


def test_next_batch_probes_then_drains_model_busy_first(tmp_path):
    be = Backend(hang=True)
    cfg, conn, gd, rvw = _setup(tmp_path, be)
    for i, pkg in enumerate(["a", "b"]):
        rid = store.record_release(conn, pkg, "1.0.0", i, False, None, "tgz")
        orchestrator._review_escalated(cfg, conn, rvw, _diff(pkg), _T, rid, guard=gd)
    be.hang = False
    gd2 = g.ReviewerGuard(cfg, be, conn, memory=None, out=lambda m: None)
    gd2.begin_batch()
    orchestrator.drain_pending(cfg, conn, rvw, auto=True, limit=1, guard=gd2)
    assert be.pings >= 1 and "b" not in _reasons(conn)              # model_busy "b" went before review_failed "a"


def test_success_feeds_the_speed_measurement(tmp_path):
    be = Backend(usage={"prompt_tokens": 10_000, "completion_tokens": 50})
    cfg, conn, gd, rvw = _setup(tmp_path, be)
    gd.tok_s = None
    rid = store.record_release(conn, "a", "1.0.0", 1, False, None, "tgz")
    orchestrator._review_escalated(cfg, conn, rvw, _diff("a"), _T, rid, guard=gd)
    assert gd.tok_s is not None and store.get_reviewer_stats(conn, cfg.reviewer.base_url, "qwen-singleshot")["samples"] == 1


def test_input_over_the_endpoint_cap_is_too_large_with_the_measured_speed(tmp_path):
    be = Backend()
    cfg, conn, gd, rvw = _setup(tmp_path, be)
    gd.tok_s = 85.0                                                 # cap ≈ 52k chars
    rid = store.record_release(conn, "big", "1.0.0", 1, False, None, "tgz")
    orchestrator._review_escalated(cfg, conn, rvw, _diff("big", "x" * 100_000), _T, rid, guard=gd)
    [row] = store.pending_reviews(conn)
    assert be.calls == 0 and row["pending_reason"] == "too_large" and "85 tok/s" in row["pending_detail"]


def test_auto_drain_reparks_rows_over_the_endpoint_cap_as_too_large(tmp_path):
    be = Backend()
    cfg, conn, gd, rvw = _setup(tmp_path, be)
    rid = store.record_release(conn, "old", "1.0.0", 1, False, None, "tgz")
    orchestrator._review_escalated(cfg, conn, rvw, _diff("old", "x" * 100_000), _T, rid, offline=True)  # parked at 200k cap
    gd.tok_s = 85.0
    orchestrator.drain_pending(cfg, conn, rvw, auto=True, guard=gd)
    assert be.calls == 0 and _reasons(conn) == {"old": "too_large"}


def test_hung_endpoint_costs_one_timeout_and_the_cursor_advances(tmp_path, monkeypatch):
    be = Backend(hang=True, ping_ok=False)
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn); store.set_last_serial(conn, 5000); conn.close()
    rels = [NewRelease(p, "1.0.0", 5001 + i) for i, p in enumerate(["a", "b", "c"])]
    monkeypatch.setattr(ingest, "changes_since", lambda *a, **k: rels)
    art = SimpleNamespace(prior_version="0.9.0", is_new_package=False, maintainer_metadata=None, prior_error=None,
                          scripts_field=None, has_lockfile=False, has_shrinkwrap=False)
    monkeypatch.setattr(fetcher, "fetch_artifacts", lambda cfg, rel: art)
    monkeypatch.setattr(orchestrator.differ, "build_diff", lambda a: _diff("x"))
    monkeypatch.setattr(orchestrator.engine, "triage", lambda *a, **k: _T)
    monkeypatch.setattr(orchestrator, "_probe_reviewer", lambda cfg: (True, "127.0.0.1:8000"))
    monkeypatch.setattr(orchestrator, "_build_reviewer", lambda cfg: reviewer.Reviewer(cfg, backend=be))
    conn = store.connect(cfg)
    store.save_reviewer_stats(conn, cfg.reviewer.base_url, cfg.reviewer.model, tok_s=1000.0, chars_per_token=3.4,
                              samples=1, state="closed", detail="", paused_until=0.0, slow_streak=0)
    conn.close()
    orchestrator.run_once(cfg, seed_if_fresh=False)
    assert be.calls == 1
    orchestrator.run_once(cfg, seed_if_fresh=False)               # next batch: probe fails -> nothing sent
    assert be.calls == 1
    conn = store.connect(cfg)
    assert store.get_last_serial(conn) == 5003          # PyPI: the cursor is the last release's serial


def test_guard_status_reads_stored_stats(tmp_path):
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn)
    store.save_reviewer_stats(conn, cfg.reviewer.base_url, cfg.reviewer.model, tok_s=85.0, chars_per_token=3.4,
                              samples=3, state="degraded", detail="degraded", paused_until=0.0, slow_streak=2)
    conn.close()
    st = orchestrator.guard_status(cfg)
    assert st["state"] == "degraded" and st["tok_s"] == 85.0 and st["cap_chars"] < 60_000


def test_chars_per_token_counts_the_system_prompt_too(tmp_path):
    """The server's prompt_tokens include the system prompt, so the chars measured against it must too;
    otherwise chars/token reads ~1.8 instead of ~3.4 on real reviews."""
    class _Sized(Backend):
        def complete(self, **kw):
            self.last_usage = {"prompt_tokens": round((len(kw["system"]) + len(kw["user_text"])) / 3.4),
                               "completion_tokens": 50}
            return _OK
    be = _Sized()
    cfg, conn, gd, rvw = _setup(tmp_path, be)
    rid = store.record_release(conn, "a", "1.0.0", 1, False, None, "tgz")
    orchestrator._review_escalated(cfg, conn, rvw, _diff("a", "x" * 20_000), _T, rid, guard=gd)
    assert 3.3 < gd.cpt < 3.5


class _Escalating(Backend):
    escalation_model = "big"

    def complete(self, **kw):
        super().complete(**kw)
        return _OK.replace('"confidence":0.9', '"confidence":0.1')


def test_escalated_review_is_not_a_speed_sample(tmp_path):
    # The elapsed time covers two models (and a llama-swap model swap); usage is the second model's.
    be = _Escalating(usage={"prompt_tokens": 10_000, "completion_tokens": 50})
    cfg, conn, gd, rvw = _setup(tmp_path, be)
    rid = store.record_release(conn, "a", "1.0.0", 1, False, None, "tgz")
    orchestrator._review_escalated(cfg, conn, rvw, _diff("a"), _T, rid, guard=gd)
    assert be.calls == 2 and gd.samples == 0 and gd.tok_s == 1000.0


def test_reviews_hold_the_review_lock_while_the_model_works(tmp_path):
    # `review-pending` and the watch loop are separate processes; one model slot must not get both.
    import fcntl
    seen = []

    class Probe(Backend):
        def complete(self, **kw):
            with open(orchestrator.review_lock_path(cfg), "a+") as f:
                try:
                    fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    seen.append("free")
                except BlockingIOError:
                    seen.append("held")
            return super().complete(**kw)

    be = Probe()
    cfg, conn, gd, rvw = _setup(tmp_path, be)
    rid = store.record_release(conn, "a", "1.0.0", 1, False, None, "tgz")
    orchestrator._review_escalated(cfg, conn, rvw, _diff("a"), _T, rid, guard=gd)
    assert seen == ["held"]


def test_auto_drain_reviews_too_large_rows_once_they_fit(tmp_path):
    # Parked over the 40k cold-start cap before calibration; once measured, the endpoint takes 200k.
    be = Backend()
    cfg, conn, gd, rvw = _setup(tmp_path, be)
    gd.tok_s = None
    rid = store.record_release(conn, "big", "1.0.0", 1, False, None, "tgz")
    orchestrator._review_escalated(cfg, conn, rvw, _diff("big", "x" * 60_000), _T, rid, guard=gd)
    assert _reasons(conn) == {"big": "too_large"}
    gd.tok_s = 7867.0
    orchestrator.drain_pending(cfg, conn, rvw, auto=True, guard=gd)
    assert be.calls == 1 and _reasons(conn) == {}


def test_auto_drain_leaves_too_large_rows_that_still_do_not_fit(tmp_path):
    be = Backend()
    cfg, conn, gd, rvw = _setup(tmp_path, be)
    rid = store.record_release(conn, "huge", "1.0.0", 1, False, None, "tgz")
    orchestrator._review_escalated(cfg, conn, rvw, _diff("huge", "x" * 300_000), _T, rid, guard=gd)
    orchestrator.drain_pending(cfg, conn, rvw, auto=True, guard=gd)
    assert be.calls == 0 and _reasons(conn) == {"huge": "too_large"}


class _CapturingMaxTokens(Backend):
    def complete(self, **kw):
        self.captured_max_tokens = kw["max_tokens"]
        return super().complete(**kw)


def _review_text(body="x" * 90_000):
    return reviewer.build_review_input(_diff("a", body), _T, max_chars=1_000_000)


def _big_review_text():
    return _review_text()


def test_max_tokens_clamped_to_the_context_window(tmp_path):
    # spec C2: an endpoint like vLLM rejects prompt + max_tokens > max_model_len with HTTP 400, so the
    # default 32000-token max_output_tokens must be clamped to what's left of a 32,768-token window.
    be = _CapturingMaxTokens()
    cfg, conn, gd, rvw = _setup(tmp_path, be)
    gd.ctx_tokens = 32_768
    rid = store.record_release(conn, "a", "1.0.0", 1, False, None, "tgz")
    orchestrator._attempt_review(cfg, conn, rvw, rid, "a", "1.0.0", 60.0, _T.fired_rules,
                                 _big_review_text(), gd)
    assert be.captured_max_tokens < cfg.reviewer.max_output_tokens
    assert be.captured_max_tokens >= 256


def test_max_tokens_unclamped_when_the_context_window_is_unknown(tmp_path):
    be = _CapturingMaxTokens()
    cfg, conn, gd, rvw = _setup(tmp_path, be)
    assert gd.ctx_tokens is None
    rid = store.record_release(conn, "a", "1.0.0", 1, False, None, "tgz")
    orchestrator._attempt_review(cfg, conn, rvw, rid, "a", "1.0.0", 60.0, _T.fired_rules,
                                 _big_review_text(), gd)
    assert be.captured_max_tokens == cfg.reviewer.max_output_tokens


def test_max_tokens_unclamped_with_no_guard(tmp_path):
    be = _CapturingMaxTokens()
    cfg, conn, gd, rvw = _setup(tmp_path, be)
    rid = store.record_release(conn, "a", "1.0.0", 1, False, None, "tgz")
    orchestrator._attempt_review(cfg, conn, rvw, rid, "a", "1.0.0", 60.0, _T.fired_rules,
                                 _big_review_text(), guard=None)
    assert be.captured_max_tokens == cfg.reviewer.max_output_tokens


class _EscalatingCapture(Backend):
    # confidence 0.1 on every call triggers escalation every time (opus_escalation_confidence default > 0.1).
    escalation_model = "big"

    def __init__(self):
        super().__init__()
        self.captured = {}

    def complete(self, **kw):
        self.calls += 1
        self.captured[kw["model"]] = kw["max_tokens"]
        self.last_usage = self.usage
        return _OK.replace('"confidence":0.9', '"confidence":0.1')

    def context_length(self, model=None):
        # The escalation model ("big") is a different id on the same endpoint with a SMALLER window than
        # the primary's — the bug this test guards against reused the primary's clamp for it.
        return {"big": 20_000}.get(model)


def test_escalation_call_clamps_against_its_own_context_window(tmp_path):
    be = _EscalatingCapture()
    cfg, conn, gd, rvw = _setup(tmp_path, be)
    gd.ctx_tokens = 32_768   # primary's window
    rid = store.record_release(conn, "a", "1.0.0", 1, False, None, "tgz")
    orchestrator._attempt_review(cfg, conn, rvw, rid, "a", "1.0.0", 60.0, _T.fired_rules,
                                 _review_text("x" * 20_000), gd)
    assert be.calls == 2
    assert be.captured["big"] < be.captured["m"]                 # escalation's smaller window bites harder
    assert be.captured["big"] < cfg.reviewer.max_output_tokens


def test_max_tokens_never_exceeds_the_configured_output_cap(tmp_path):
    # The 256-token floor must never push max_tokens above a smaller configured max_output_tokens.
    be = _CapturingMaxTokens()
    cfg, conn, gd, rvw = _setup(tmp_path, be, max_output_tokens=200)
    gd.ctx_tokens = 1_000_000   # plenty of room, so the floor (not the window) would otherwise dominate
    rid = store.record_release(conn, "a", "1.0.0", 1, False, None, "tgz")
    orchestrator._attempt_review(cfg, conn, rvw, rid, "a", "1.0.0", 60.0, _T.fired_rules,
                                 _review_text("x" * 100), gd)
    assert be.captured_max_tokens == 200


def test_upgrade_backfills_the_length_of_already_parked_inputs(tmp_path):
    # Rows parked before review_input_chars existed must still become eligible once they fit.
    import zlib
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn)
    rid = store.record_release(conn, "old", "1.0.0", 1, False, None, "tgz")
    store.park_for_review(conn, rid, "too_large", "needs 5 chars", "hello")
    conn.execute("ALTER TABLE releases DROP COLUMN review_input_chars")
    conn.execute("UPDATE releases SET review_input=? WHERE id=?", (zlib.compress(b"hello"), rid))
    store.migrate_schema(conn)
    assert [r["release_id"] for r in store.pending_reviews(conn, ("too_large",), max_chars=5)] == [rid]
