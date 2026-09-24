"""spec U2: a benign verdict on truncated review input is not final. If the input cap dropped a file
that carried fired-rule weight, the model never saw it — the release goes to needs_adjudication with
"reviewed partially: <files> not shown" instead of being saved silently, and alerts once."""
import json
from pydiffwatch.config import Config, ReviewerConfig
from pydiffwatch import store, orchestrator, reviewer
from pydiffwatch.models import Diff, FileDiff, Hunk, FiredRule, TriageResult


class _FakeBackend:
    """A scripted review backend (mirrors tests/test_reviewer.py's fake)."""
    def __init__(self, scripted, primary="claude-sonnet-4-6", escalation=None):
        self.scripted = list(scripted)
        self.primary_model = primary
        self.escalation_model = escalation
        self.calls = []
    def complete(self, **kw):
        self.calls.append(kw)
        return self.scripted.pop(0)


def _benign_json(reasoning="looks fine"):
    return json.dumps({"classification": "benign", "confidence": 0.8, "urgent": False,
                       "recommended_action": "dismiss", "attack_type": "none",
                       "cited_hunk": "setup.py:1-1", "reasoning": reasoning})


def _setup(tmp_path, max_input_chars=10_000):
    cfg = Config(db_path=tmp_path / "o.sqlite", lock_path=tmp_path / "l",
                reviewer=ReviewerConfig(max_input_chars=max_input_chars))
    conn = store.connect(cfg); store.init_schema(conn)
    rid = store.record_release(conn, "p", "1.0", 1, False, "0.9", "sdist")
    return cfg, conn, rid


def _alert_count(conn):
    return conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]


def test_truncated_input_with_dropped_weighted_file_goes_to_adjudication(tmp_path):
    small = FileDiff("setup.py", "modified", [Hunk((0, 0), (0, 1), ["os.system('id')"], [])])
    big = FileDiff("big.py", "modified", [Hunk((0, 0), (0, 1), ["X" * 3000], [])])
    d = Diff("p", "1.0", False, [small, big], [])
    tr = TriageResult(50.0, [FiredRule("autoexec", 50.0, "setup.py", (1, 1)),
                             FiredRule("autoexec", 40.0, "big.py", (1, 1))], True)
    cfg, conn, rid = _setup(tmp_path, max_input_chars=500)   # big.py can't fit; setup.py can
    rvw = reviewer.Reviewer(cfg, backend=_FakeBackend([_benign_json()]))

    orchestrator._review_escalated(cfg, conn, rvw, d, tr, rid)

    assert store.get_stage(conn, "p", "1.0") == "needs_adjudication"
    row = conn.execute("SELECT classification, reasoning FROM verdicts WHERE release_id=?", (rid,)).fetchone()
    assert row["classification"] == "benign"                 # the model's actual verdict is kept
    assert "reviewed partially" in row["reasoning"] and "big.py" in row["reasoning"]
    assert _alert_count(conn) == 1
    alert = conn.execute("SELECT classification FROM alerts WHERE release_id=?", (rid,)).fetchone()
    assert alert["classification"] == "suspicious-heuristic"


def test_truncated_input_with_only_zero_weight_files_dropped_stays_benign(tmp_path):
    flagged = FileDiff("setup.py", "modified", [Hunk((0, 0), (0, 1), ["os.system('id')"], [])])
    unflagged = FileDiff("README.md", "modified", [Hunk((0, 0), (0, 1), ["just docs"], [])])
    d = Diff("p", "1.0", False, [flagged, unflagged], [])
    tr = TriageResult(50.0, [FiredRule("autoexec", 50.0, "setup.py", (1, 1))], True)
    cfg, conn, rid = _setup(tmp_path, max_input_chars=10_000)   # everything flagged fits comfortably
    rvw = reviewer.Reviewer(cfg, backend=_FakeBackend([_benign_json()]))

    orchestrator._review_escalated(cfg, conn, rvw, d, tr, rid)

    # README.md is dropped (unflagged, weight 0) and the text does carry TRUNCATION_NOTE, but that
    # dropped file carries no fired-rule weight, so the benign verdict stands.
    assert store.get_stage(conn, "p", "1.0") == "reviewed"
    row = conn.execute("SELECT classification, reasoning FROM verdicts WHERE release_id=?", (rid,)).fetchone()
    assert row["classification"] == "benign"
    assert "reviewed partially" not in (row["reasoning"] or "")
    assert _alert_count(conn) == 0


def test_untruncated_input_with_benign_verdict_stays_benign(tmp_path):
    flagged = FileDiff("setup.py", "modified", [Hunk((0, 0), (0, 1), ["os.system('id')"], [])])
    d = Diff("p", "1.0", False, [flagged], [])
    tr = TriageResult(50.0, [FiredRule("autoexec", 50.0, "setup.py", (1, 1))], True)
    cfg, conn, rid = _setup(tmp_path, max_input_chars=10_000)
    rvw = reviewer.Reviewer(cfg, backend=_FakeBackend([_benign_json()]))

    orchestrator._review_escalated(cfg, conn, rvw, d, tr, rid)

    assert store.get_stage(conn, "p", "1.0") == "reviewed"
    assert _alert_count(conn) == 0
