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
