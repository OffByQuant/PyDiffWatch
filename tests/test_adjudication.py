"""§8.1 verdict routing + agent adjudication queue. Running inside a Claude Code session, a model
`suspicious` verdict is queued (not alerted) for the agent to review and label; benign is saved
silently; malicious alerts immediately."""
from pydiffwatch import orchestrator, store, fetcher
from pydiffwatch.config import Config
from pydiffwatch.models import Verdict, Diff, TriageResult, FiredRule


class _FakeRvw:
    def __init__(self, verdict): self._v = verdict
    def review(self, d, tr): return self._v


def _setup(tmp_path, classification):
    cfg = Config(db_path=tmp_path / "db.sqlite", cache_dir=tmp_path / "c", lock_path=tmp_path / "l")
    conn = store.connect(cfg); store.init_schema(conn)
    rid = store.record_release(conn, "p", "1.0", 5, False, None, "sdist")
    d = Diff("p", "1.0", False, [], [])
    tr = TriageResult(50.0, [FiredRule("autoexec", 50.0, "setup.py", (1, 2))], True)
    v = Verdict("p", "1.0", classification, 50.0, tr.fired_rules, False, confidence=0.9,
                attack_type="install-hook-rce", reasoning="model says...", model="qwen-singleshot")
    return cfg, conn, rid, d, tr, v


def _alert_count(conn):
    return conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]


def test_benign_saved_silently_no_alert(tmp_path):
    cfg, conn, rid, d, tr, v = _setup(tmp_path, "benign")
    orchestrator._review_escalated(cfg, conn, _FakeRvw(v), d, tr, rid)
    assert store.get_stage(conn, "p", "1.0") == "reviewed"
    assert _alert_count(conn) == 0
    assert conn.execute("SELECT COUNT(*) FROM verdicts").fetchone()[0] == 1   # still persisted


def test_malicious_alerts_immediately(tmp_path):
    cfg, conn, rid, d, tr, v = _setup(tmp_path, "malicious")
    orchestrator._review_escalated(cfg, conn, _FakeRvw(v), d, tr, rid)
    assert store.get_stage(conn, "p", "1.0") == "reviewed"
    assert _alert_count(conn) == 1


def test_suspicious_queued_not_alerted(tmp_path):
    cfg, conn, rid, d, tr, v = _setup(tmp_path, "suspicious")
    orchestrator._review_escalated(cfg, conn, _FakeRvw(v), d, tr, rid)
    assert store.get_stage(conn, "p", "1.0") == "needs_adjudication"
    assert _alert_count(conn) == 0
    pend = store.pending_adjudication(conn)
    assert len(pend) == 1 and pend[0]["package"] == "p" and pend[0]["classification"] == "suspicious"


def test_adjudicate_malicious_emits_alert_and_resolves(tmp_path):
    cfg, conn, rid, d, tr, v = _setup(tmp_path, "suspicious")
    orchestrator._review_escalated(cfg, conn, _FakeRvw(v), d, tr, rid)
    conn.close()
    res = orchestrator.adjudicate(cfg, rid, "malicious", "confirmed download-and-run dropper")
    assert res["alerted"] is True and res["label"] == "malicious"
    conn = store.connect(cfg)
    row = conn.execute("SELECT human_label, human_note FROM verdicts WHERE release_id=?", (rid,)).fetchone()
    assert row[0] == "malicious" and "dropper" in row[1]
    assert _alert_count(conn) == 1
    assert store.pending_adjudication(conn) == []                            # resolved -> off the queue


def test_adjudicate_benign_clears_without_alert(tmp_path):
    cfg, conn, rid, d, tr, v = _setup(tmp_path, "suspicious")
    orchestrator._review_escalated(cfg, conn, _FakeRvw(v), d, tr, rid)
    conn.close()
    res = orchestrator.adjudicate(cfg, rid, "benign", "false positive: legit GraphQL client")
    assert res["alerted"] is False
    conn = store.connect(cfg)
    assert _alert_count(conn) == 0
    assert store.pending_adjudication(conn) == []


def test_list_pending_surfaces_queue(tmp_path, monkeypatch):
    cfg, conn, rid, d, tr, v = _setup(tmp_path, "suspicious")
    orchestrator._review_escalated(cfg, conn, _FakeRvw(v), d, tr, rid)
    conn.close()
    monkeypatch.setattr(fetcher, "fetch_artifacts", lambda cfg, rel: None)   # diff unavailable path
    items = orchestrator.list_pending(cfg)
    assert len(items) == 1
    assert items[0]["package"] == "p" and items[0]["classification"] == "suspicious"
    assert items[0]["diff_text"] is None
