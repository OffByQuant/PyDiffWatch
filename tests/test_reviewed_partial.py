"""Spec F §3.4: reviewed_partial, the chain columns, and review_shown travelling with the stored input."""
import dataclasses

import pytest

from pydiffwatch import store
from pydiffwatch.config import Config
from pydiffwatch.models import Verdict
from tests.fixtures import chains


def _cfg(tmp_path):
    return Config(db_path=tmp_path / "db.sqlite", lock_path=tmp_path / "l", cache_dir=tmp_path / "c")


def _conn(tmp_path):
    conn = store.connect(_cfg(tmp_path)); store.init_schema(conn)
    return conn


def test_the_verdict_keeps_its_chain_and_the_gate(tmp_path):
    conn = _conn(tmp_path)
    rid = store.record_release(conn, "p", "1", 1, False, None, "sdist")
    v = Verdict("p", "1", "suspicious", 1.0, [], False, model="m", **dict(chains.FIELDS, chain_source="x" * 3_000),
                gate="no dataflow shown between source and sink")
    store.record_verdict(conn, rid, v)
    row = conn.execute("SELECT runs_when, source_kind, sink_kind, chain_source, chain_sink, gate FROM verdicts").fetchone()
    assert (row[0], row[1], row[2], len(row[3]), row[4], row[5]) == (
        "build", "secret-read", "send", 2_000, chains.SINK, "no dataflow shown between source and sink")


def test_review_shown_is_written_kept_and_cleared_with_the_input(tmp_path):
    conn = _conn(tmp_path)
    rid = store.record_release(conn, "p", "1", 1, False, None, "sdist")
    store.park_for_review(conn, rid, "in_review", "d", "text", chains.SHOWN)
    assert store.review_shown(conn, rid) == chains.SHOWN
    store.park_for_review(conn, rid, "model_busy", "d", "text")           # a re-park keeps it (Ruling F10)
    store.set_pending_reason(conn, rid, "review_failed", "d")
    assert store.review_shown(conn, rid) == chains.SHOWN
    store.park_for_review(conn, rid, "reviewer_disabled", "d", "", None)   # None stores NULL
    assert store.review_shown(conn, rid) is None
    store.park_for_review(conn, rid, "in_review", "d", "text", chains.SHOWN)
    store.clear_pending(conn, rid)
    assert store.review_shown(conn, rid) is None


def test_reviewed_partial_is_listed_kept_and_an_sdist_stage(tmp_path):
    conn = _conn(tmp_path)
    rid = store.record_release(conn, "p", "1", 1, False, None, "sdist")
    store.record_verdict(conn, rid, Verdict("p", "1", "benign", 1.0, [], False, model="m",
                                            reasoning="reviewed partially: a.py not shown or unreadable. Model: ok"))
    store.update_stage(conn, rid, "reviewed_partial")
    store.update_evidence(conn, rid, "package: p\n+ exec(x)")
    assert [r["release_id"] for r in store.pending_adjudication(conn)] == [rid]
    assert "reviewed_partial" in store.SDIST_STAGES
    store.prune(conn, retention_days=1)
    assert store.get_evidence(conn, rid) is not None
    [row] = store.all_verdicts(conn)
    assert row["stage"] == "reviewed_partial" and "gate" in row.keys() and "chain_source" in row.keys()


def test_the_migration_adds_the_columns_to_an_old_database(tmp_path):
    conn = _conn(tmp_path)
    conn.execute("ALTER TABLE verdicts DROP COLUMN gate"); conn.execute("ALTER TABLE releases DROP COLUMN review_shown")
    conn.commit()
    store.migrate_schema(conn)
    conn.execute("SELECT gate FROM verdicts"); conn.execute("SELECT review_shown FROM releases")


# ---- the routing table (spec F §3.4) ----
import json

from pydiffwatch import orchestrator, reviewer
from pydiffwatch.models import Diff, FileDiff, FiredRule, Hunk, TriageResult


def _rid(conn):
    return store.record_release(conn, "p", "1", 1, False, "0.9", "sdist")


def _stage(conn):
    return store.get_stage(conn, "p", "1")


def _alerts(conn):
    return [r[0] for r in conn.execute("SELECT classification FROM alerts")]


def _v(cls, **kw):
    return Verdict("p", "1", cls, 50.0, [], cls == "malicious", confidence=0.95, model="m", reasoning="r", **kw)


@pytest.mark.parametrize("cls, chained, blind, stage, alerts", [
    ("benign", False, False, "reviewed", []),
    ("benign", False, True, "reviewed_partial", []),
    ("suspicious", False, True, "reviewed_partial", []),
    ("suspicious", False, False, "needs_adjudication", []),
    ("suspicious", True, True, "needs_adjudication", []),
    ("malicious", True, False, "reviewed", ["malicious"]),
    ("malicious", True, True, "reviewed", ["malicious"]),
    ("malicious", False, True, "needs_adjudication", ["suspicious"]),
])
def test_the_routing_table(tmp_path, cls, chained, blind, stage, alerts):
    conn = _conn(tmp_path)
    rid = _rid(conn)
    v = _v(cls, **(chains.FIELDS if chained else {"runs_when": "build"}))
    orchestrator._record(_cfg(tmp_path), conn, rid, v, 50.0, dropped=["pkg/b.py"] if blind else (),
                         shown=chains.SHOWN)
    assert (_stage(conn), _alerts(conn)) == (stage, alerts)


def test_a_failed_gate_downgrades_with_its_reason_and_keeps_the_quotes(tmp_path):
    conn = _conn(tmp_path)
    rid = _rid(conn)
    orchestrator._record(_cfg(tmp_path), conn, rid, _v("malicious", **dict(chains.FIELDS, sink_kind="exec")), 50.0,
                         shown=chains.SHOWN)
    row = conn.execute("SELECT classification, reasoning, gate, chain_sink FROM verdicts").fetchone()
    assert row[0] == "suspicious" and row[2] == "sink quoted as exec, but the quoted lines show no exec"
    assert row[1].startswith("model said malicious (downgraded: sink quoted as exec") and row[3] == chains.SINK
    assert _alerts(conn) == ["suspicious"] and _stage(conn) == "needs_adjudication"


@pytest.mark.parametrize("runs_when", ["unknown", None, "user-command", "not-shipped"])
def test_weak_runs_when_downgrades_a_passing_chain(tmp_path, runs_when):
    conn = _conn(tmp_path)
    rid = _rid(conn)
    orchestrator._record(_cfg(tmp_path), conn, rid, _v("malicious", **dict(chains.FIELDS, runs_when=runs_when)), 50.0,
                         shown=chains.SHOWN)
    assert _alerts(conn) == ["suspicious"]


def test_the_unreviewed_verdict_never_becomes_partial(tmp_path):
    # review C2: a binary-only fire keeps its no_content alert
    conn = _conn(tmp_path)
    rid = _rid(conn)
    v = Verdict("p", "1", "suspicious", 50.0, [], False, confidence=0.0, model="none",
                reasoning="UNREVIEWED: triage fired (bin) but none of the flagged content could be shown")
    orchestrator._record(_cfg(tmp_path), conn, rid, v, 50.0, unreadable=["pkg/_c.so"])
    assert _stage(conn) == "needs_adjudication"
    assert conn.execute("SELECT dedupe_key FROM alerts").fetchone()[0].endswith("unscanned:no_content")


class _Backend:
    primary_model, escalation_model = "m", None

    def __init__(self, replies):
        self.replies = list(replies)

    def complete(self, **kw):
        return self.replies.pop(0)


def _json(cls, **kw):
    return json.dumps({"classification": cls, "confidence": 0.95, "urgent": False, "recommended_action": "monitor",
                       "attack_type": "none", "cited_hunk": "", "reasoning": "r", "runs_when": "build", **kw})


def test_a_benign_verdict_with_unshown_runnable_files_is_partial(tmp_path):
    # Review Focus 3
    conn = _conn(tmp_path)
    rid = _rid(conn)
    files = [FileDiff("pkg/_boot.py", "modified", [Hunk((0, 0), (0, 1), ["exec(x)"], [])], "exec(x)\n")] + [
        FileDiff(f"pkg/m{i}.py", "modified", [Hunk((0, 0), (0, 40), ["v = 1"] * 40, [])], "v = 1\n" * 40)
        for i in range(50)]
    tr = TriageResult(40.0, [FiredRule("r", 40.0, "pkg/_boot.py", (1, 1))], True)
    cfg = dataclasses.replace(_cfg(tmp_path), reviewer=dataclasses.replace(Config().reviewer, max_input_chars=6_000))
    orchestrator._review_escalated(cfg, conn, reviewer.Reviewer(cfg, backend=_Backend([_json("benign")])),
                                   Diff("p", "1", False, files, []), tr, rid)
    assert _stage(conn) == "reviewed_partial"
    assert conn.execute("SELECT reasoning FROM verdicts").fetchone()[0].startswith("reviewed partially: pkg/m")


def test_the_review_path_passes_the_shown_lines_to_the_gate(tmp_path):
    conn = _conn(tmp_path)
    rid = _rid(conn)
    tr = TriageResult(40.0, [FiredRule("r", 40.0, "setup.py", (3, 4))], True)
    cfg = _cfg(tmp_path)
    orchestrator._review_escalated(cfg, conn, reviewer.Reviewer(cfg, backend=_Backend([_json("malicious", **chains.JSON_FIELDS)])),
                                   Diff("p", "1", False, [chains.FILE], []), tr, rid)
    assert _alerts(conn) == ["malicious"]


def test_the_drain_gates_against_the_stored_shown_lines(tmp_path):
    conn = _conn(tmp_path)
    rid = _rid(conn)
    tr = TriageResult(40.0, [FiredRule("r", 40.0, "setup.py", (3, 4))], True)
    store.update_stage(conn, rid, "triaged", tr.score, json.dumps([r.__dict__ for r in tr.fired_rules]))
    cfg = _cfg(tmp_path)
    orchestrator._review_escalated(cfg, conn, reviewer.Reviewer(cfg, backend=_Backend([])),
                                   Diff("p", "1", False, [chains.FILE], []), tr, rid, offline=True)
    assert store.review_shown(conn, rid)["setup.py"]["cls"] == "build"
    orchestrator.drain_pending(cfg, conn, reviewer.Reviewer(cfg, backend=_Backend([_json("malicious", **chains.JSON_FIELDS)])),
                               auto=True)
    assert _alerts(conn) == ["malicious"]


def _pre_f_park(conn, rid, text, rules):
    store.update_stage(conn, rid, "triaged", 50.0, json.dumps(rules))
    store.park_for_review(conn, rid, "endpoint_unreachable", "d", text, None)


_PRE_F = ("package: p\nversion: 1\nis_first_release: False\ntriage_score: 50\nuntrusted_content_marker: ===DW-UNTRUSTED-"
          + "0" * 32 + "===\n\n===DW-UNTRUSTED-" + "0" * 32 + "===\n--- file: setup.py (modified) ---\n@@ new L3-4\n+ "
          + chains.SOURCE + "\n+ " + chains.SINK + "\n===DW-UNTRUSTED-" + "0" * 32 + "===")


def test_a_pre_f_stored_input_is_gated_as_unclassified(tmp_path):
    # Review Focus 2
    conn = _conn(tmp_path)
    rid = _rid(conn)
    _pre_f_park(conn, rid, _PRE_F, [{"rule": "r", "weight": 50.0, "file": "setup.py", "lines": [3, 4]}])
    cfg = _cfg(tmp_path)
    orchestrator.drain_pending(cfg, conn, reviewer.Reviewer(cfg, backend=_Backend([_json("malicious", **chains.JSON_FIELDS)])),
                               auto=True)
    assert conn.execute("SELECT gate FROM verdicts").fetchone()[0] == "chain is in unclassified code (setup.py)"
    assert _alerts(conn) == ["suspicious"]


def test_a_pre_f_stored_input_with_a_dropped_weighted_file_is_partial(tmp_path):
    # Review Focus 2 (Ruling F11)
    conn = _conn(tmp_path)
    rid = _rid(conn)
    _pre_f_park(conn, rid, _PRE_F, [{"rule": "r", "weight": 50.0, "file": "setup.py", "lines": [3, 4]},
                                    {"rule": "r", "weight": 40.0, "file": "big.py", "lines": [1, 1]}])
    cfg = _cfg(tmp_path)
    orchestrator.drain_pending(cfg, conn, reviewer.Reviewer(cfg, backend=_Backend([_json("benign")])), auto=True)
    assert _stage(conn) == "reviewed_partial"


def test_pending_lists_a_partial_review(tmp_path, monkeypatch, capsys):
    conn = _conn(tmp_path)
    rid = _rid(conn)
    orchestrator._record(_cfg(tmp_path), conn, rid, _v("benign", runs_when="build"), 50.0, dropped=["pkg/b.py"])
    store.update_evidence(conn, rid, "package: p\n+ exec(x)")          # stored evidence: list_pending fetches nothing
    [item] = orchestrator.list_pending(_cfg(tmp_path))
    assert item["partial"] is True and item["not_scanned"] is None


# ---- Task 10 fix round 1 ----

def _gate_raises(monkeypatch):
    def boom(v, s):
        raise RuntimeError("bug")
    monkeypatch.setattr(orchestrator.chain, "gate", boom)


def _downgraded_by_the_error(conn):
    assert [r[0] for r in conn.execute("SELECT dedupe_key FROM alerts")] == ["p|1|suspicious|downgraded"]
    assert tuple(conn.execute("SELECT classification, gate, chain_sink FROM verdicts").fetchone()) == (
        "suspicious", "gate error (RuntimeError)", chains.SINK)
    assert _stage(conn) == "needs_adjudication" and store.pending_reviews(conn) == []


def test_a_gate_error_on_the_review_path_downgrades(tmp_path, monkeypatch):
    # J1: a raising gate never loses the model's verdict or the stored input
    conn = _conn(tmp_path)
    rid = _rid(conn)
    _gate_raises(monkeypatch)
    tr = TriageResult(40.0, [FiredRule("r", 40.0, "setup.py", (3, 4))], True)
    cfg = _cfg(tmp_path)
    orchestrator._review_escalated(cfg, conn, reviewer.Reviewer(cfg, backend=_Backend([_json("malicious", **chains.JSON_FIELDS)])),
                                   Diff("p", "1", False, [chains.FILE], []), tr, rid)
    _downgraded_by_the_error(conn)


def test_a_gate_error_on_the_drain_downgrades_and_leaves_the_queue(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    rid = _rid(conn)
    tr = TriageResult(40.0, [FiredRule("r", 40.0, "setup.py", (3, 4))], True)
    store.update_stage(conn, rid, "triaged", tr.score, json.dumps([r.__dict__ for r in tr.fired_rules]))
    cfg = _cfg(tmp_path)
    orchestrator._review_escalated(cfg, conn, reviewer.Reviewer(cfg, backend=_Backend([])),
                                   Diff("p", "1", False, [chains.FILE], []), tr, rid, offline=True)
    _gate_raises(monkeypatch)
    for _ in range(3):      # later drains find nothing queued, and never raise on a wiped row
        orchestrator.drain_pending(cfg, conn, reviewer.Reviewer(
            cfg, backend=_Backend([_json("malicious", **chains.JSON_FIELDS)])), auto=True)
    _downgraded_by_the_error(conn)


def test_a_clipped_not_shown_block_yields_only_full_names():
    # J2: a name cut by the block cap ('…') is not a path
    paths = ["a.py"] + [f"pkg/very/long/module_name_{i:03d}.py" for i in range(39)]
    block = reviewer._render_block(reviewer._NOT_SHOWN_HEADING, "\n".join(p + " (runtime)" for p in paths), 1_200)
    names, _ = reviewer.not_seen_from_text(block)
    assert "a.py" in names and not any(n.endswith("…") for n in names)


def test_a_block_whose_every_name_is_clipped_still_says_files_were_not_shown():
    # J2 guard: dropping clipped names must never make a drained benign verdict look fully seen
    paths = [f"pkg/very/long/module_name_{i:03d}.py" for i in range(40)]
    block = reviewer._render_block(reviewer._NOT_SHOWN_HEADING, "\n".join(p + " (runtime)" for p in paths), 1_200)
    names, _ = reviewer.not_seen_from_text(block)
    assert names == ["(file names clipped)"]
