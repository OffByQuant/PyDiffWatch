"""Task 13 (spec B5, B6, B7, decision 2): confidence anchors, `runs_when`, schema defaults, and a weak `malicious`
verdict downgraded to `suspicious` with "needs manual review", waiting in `pending` for a person."""
import argparse
import json
import math

import pytest

from pydiffwatch import __main__ as cli
from pydiffwatch import dashboard, execctx, orchestrator, reviewer, store
from pydiffwatch.backends import ReviewUnavailable, validate_verdict
from pydiffwatch.config import Config, ReviewerConfig, load_config
from pydiffwatch.models import Diff, FileDiff, FiredRule, Hunk, TriageResult, Verdict

RUNS_WHEN = ["build", "startup", "import", "user-command", "plugin-host", "runtime-call", "not-shipped", "unknown"]


class _FakeBackend:
    def __init__(self, scripted, primary="m", escalation=None):
        self.scripted = list(scripted)
        self.primary_model = primary
        self.escalation_model = escalation

    def complete(self, **kw):
        text = self.scripted.pop(0)
        validate_verdict(json.loads(text), kw["schema"])     # as both real backends do
        return text


def _diff():
    h = Hunk((0, 0), (0, 3), ["import os", "import requests", "exec(requests.get(U).text)"], [])
    return Diff("evilpkg", "1.3.0", False, [FileDiff("setup.py", "modified", [h])], [])


def _triage():
    return TriageResult(60.0, [FiredRule("combo:fetch+exec", 45.0, "setup.py", (1, 3))], True)


def _review(d):
    return reviewer.Reviewer(Config(), backend=_FakeBackend([json.dumps(d)])).review(_diff(), _triage())


def _full(**kw):
    d = {"runs_when": "build", "classification": "malicious", "confidence": 0.95, "urgent": True,
         "recommended_action": "report-to-pypi", "attack_type": "install-hook-rce",
         "cited_hunk": "setup.py:1-3", "reasoning": "fetch+exec in setup.py"}
    d.update(kw)
    return d


# ---- schema and prompt (B5) ----

def test_runs_when_enum_comes_before_classification():
    props = reviewer.REVIEW_SCHEMA["properties"]
    assert props["runs_when"]["enum"] == RUNS_WHEN
    keys = list(props)
    assert keys.index("runs_when") < keys.index("classification")
    assert "runs_when" in reviewer.REVIEW_SCHEMA["required"]


def test_prompt_names_every_runs_when_value_and_the_confidence_anchors():
    sp = reviewer.SYSTEM_PROMPT
    for val in RUNS_WHEN:
        assert val in sp
    assert "1.0 only when" in sp and "source" in sp and "sink" in sp and "runs unasked" in sp
    assert "at most 0.6" in sp and "inferred" in sp


def test_prompt_does_not_treat_the_import_line_as_complete():
    sp = reviewer.SYSTEM_PROMPT
    assert "import line" in sp and "may be incomplete" in sp


# ---- schema defaults (B6): only classification is mandatory ----

def test_only_classification_is_mandatory():
    validate_verdict({"classification": "benign"}, reviewer.REVIEW_SCHEMA)          # no raise
    with pytest.raises(ReviewUnavailable):
        validate_verdict({"runs_when": "build", "confidence": 0.9}, reviewer.REVIEW_SCHEMA)


def test_a_truncated_tail_keeps_the_verdict():
    v = _review({"runs_when": "build", "classification": "malicious"})
    assert v.classification == "malicious" and v.runs_when == "build"
    assert v.confidence is None and v.attack_type == "none" and v.urgent is False
    assert v.reasoning == "" and v.cited_hunk == ""
    assert v.recommended_action == "report-to-pypi"


@pytest.mark.parametrize("d", [{"classification": "benign"}, {"runs_when": "at-install", "classification": "benign"}])
def test_a_missing_or_invalid_runs_when_is_unknown(d):
    assert _review(d).runs_when == "unknown"


@pytest.mark.parametrize("raw", ["high", None, True, float("nan"), float("inf"), 10**400])
def test_an_unparseable_confidence_is_none(raw):
    assert _review(_full(confidence=raw)).confidence is None


def test_nan_literal_confidence_is_never_read_as_certain():
    text = json.dumps(_full()).replace("0.95", "NaN")        # json.loads accepts a bare NaN
    v = reviewer.Reviewer(Config(), backend=_FakeBackend([text])).review(_diff(), _triage())
    assert v.confidence is None


# ---- B7: malicious always carries report-to-pypi ----

@pytest.mark.parametrize("action", ["monitor", "dismiss", "block_and_report"])
def test_malicious_always_maps_to_report(action):
    assert _review(_full(recommended_action=action)).recommended_action == "report-to-pypi"


def test_a_non_malicious_verdict_keeps_its_action():
    assert _review(_full(classification="suspicious", recommended_action="dismiss")).recommended_action == "dismiss"


# ---- decision 2: weak malicious is downgraded ----

def _setup(tmp_path, **rv):
    cfg = Config(db_path=tmp_path / "o.sqlite", lock_path=tmp_path / "l", reviewer=ReviewerConfig(**rv))
    conn = store.connect(cfg); store.init_schema(conn)
    rid = store.record_release(conn, "evilpkg", "1.3.0", 1, False, "1.2.0", "sdist")
    store.update_evidence(conn, rid, "package: evilpkg\n+ exec(x)")
    return cfg, conn, rid


def _verdict(runs_when="build", confidence=0.95):
    return Verdict("evilpkg", "1.3.0", "malicious", 60.0, [FiredRule("combo", 45.0, "setup.py", (1, 3))], True,
                   confidence=confidence, attack_type="install-hook-rce", reasoning="fetch+exec in setup.py",
                   cited_hunk="setup.py:1-3", recommended_action="report-to-pypi", model="m", runs_when=runs_when)


def _alerts(conn):
    return [dict(r) for r in conn.execute("SELECT classification, dedupe_key FROM alerts")]


def _row(conn, rid):
    return conn.execute("SELECT classification, reasoning, confidence FROM verdicts WHERE release_id=?",
                        (rid,)).fetchone()


@pytest.mark.parametrize("runs_when, confidence", [("build", 0.95), ("unknown", 0.95), ("import", 0.8),
                                                   ("startup", 1.0)])
def test_a_strong_malicious_alerts_as_malicious(tmp_path, runs_when, confidence):
    cfg, conn, rid = _setup(tmp_path)
    orchestrator._record(cfg, conn, rid, _verdict(runs_when, confidence), 60.0)
    assert [a["classification"] for a in _alerts(conn)] == ["malicious"]
    assert _row(conn, rid)["classification"] == "malicious"
    assert store.get_stage(conn, "evilpkg", "1.3.0") == "reviewed"


@pytest.mark.parametrize("runs_when, confidence, why", [
    ("user-command", 0.95, "runs_when=user-command"),
    ("not-shipped", 1.0, "runs_when=not-shipped"),
    ("build", 0.79, "confidence 0.79 < 0.8"),
    ("unknown", None, "no confidence"),
])
def test_a_weak_malicious_is_downgraded_to_suspicious_for_manual_review(tmp_path, runs_when, confidence, why):
    cfg, conn, rid = _setup(tmp_path)
    orchestrator._record(cfg, conn, rid, _verdict(runs_when, confidence), 60.0)
    alerts = _alerts(conn)
    assert [a["classification"] for a in alerts] == ["suspicious"]           # never alerts as malicious
    row = _row(conn, rid)
    assert row["classification"] == "suspicious"
    assert f"model said malicious (downgraded: {why})" in row["reasoning"]   # the model's label stays visible
    assert "needs manual review" in row["reasoning"]
    assert "fetch+exec in setup.py" in row["reasoning"]                      # and its own reasoning
    assert store.get_stage(conn, "evilpkg", "1.3.0") == "needs_adjudication"
    assert store.get_evidence(conn, rid) is not None                         # kept for the person who acts
    [item] = orchestrator.list_pending(cfg)                                  # waits in `pending`
    assert item["classification"] == "suspicious" and item["not_scanned"] is None
    dash = dict(row) | {"stage": "needs_adjudication", "human_label": None}
    assert dashboard.is_flagged(dash)
    assert not dashboard.is_flagged(dash | {"human_label": "benign"})


def test_a_downgraded_verdict_is_not_urgent(tmp_path, monkeypatch):
    cfg, conn, rid = _setup(tmp_path)
    emitted = []
    monkeypatch.setattr(orchestrator.notifier, "emit", lambda cfg, conn, v, rid, **kw: emitted.append(v))
    orchestrator._record(cfg, conn, rid, _verdict("user-command"), 60.0)
    assert conn.execute("SELECT urgent FROM verdicts WHERE release_id=?", (rid,)).fetchone()["urgent"] == 0
    assert [v.urgent for v in emitted] == [False]


def test_the_downgraded_alert_text_says_needs_manual_review(tmp_path, capsys):
    cfg, conn, rid = _setup(tmp_path)
    orchestrator._record(cfg, conn, rid, _verdict("user-command"), 60.0)
    out = capsys.readouterr().out
    assert "[DIFFWATCH] suspicious" in out and "needs manual review" in out and "malicious score" not in out


def test_a_downgraded_verdict_alerts_once_across_re_records(tmp_path):
    cfg, conn, rid = _setup(tmp_path)
    orchestrator._record(cfg, conn, rid, _verdict("user-command"), 60.0)
    orchestrator._record(cfg, conn, rid, _verdict("user-command"), 60.0)
    assert len(_alerts(conn)) == 1


def test_prune_keeps_a_downgraded_verdict_and_its_evidence(tmp_path):
    cfg, conn, rid = _setup(tmp_path)
    orchestrator._record(cfg, conn, rid, _verdict("not-shipped"), 60.0)
    store.prune(conn, retention_days=1)
    assert _row(conn, rid)["classification"] == "suspicious" and store.get_evidence(conn, rid) is not None


def test_the_threshold_is_configurable(tmp_path):
    cfg, conn, rid = _setup(tmp_path, malicious_min_confidence=0.5)
    orchestrator._record(cfg, conn, rid, _verdict("build", 0.6), 60.0)
    assert [a["classification"] for a in _alerts(conn)] == ["malicious"]


def test_a_downgrade_through_the_review_path(tmp_path):
    cfg, conn, rid = _setup(tmp_path)
    rvw = reviewer.Reviewer(cfg, backend=_FakeBackend([json.dumps(_full(runs_when="user-command"))]))
    orchestrator._review_escalated(cfg, conn, rvw, _diff(), _triage(), rid)
    assert [a["classification"] for a in _alerts(conn)] == ["suspicious"]
    assert store.get_stage(conn, "evilpkg", "1.3.0") == "needs_adjudication"


# ---- config ----

def test_malicious_min_confidence_defaults_to_0_8_and_loads_from_toml(tmp_path):
    assert ReviewerConfig().malicious_min_confidence == 0.8
    p = tmp_path / "c.toml"
    p.write_text("[reviewer]\nmalicious_min_confidence = 0.65\n")
    assert load_config(p).reviewer.malicious_min_confidence == 0.65


@pytest.mark.parametrize("bad", ["1.5", "-0.1", '"high"', "true", "nan"])
def test_an_out_of_range_malicious_min_confidence_is_refused(tmp_path, bad):
    p = tmp_path / "c.toml"
    p.write_text(f"[reviewer]\nmalicious_min_confidence = {bad}\n")
    with pytest.raises(ValueError, match="malicious_min_confidence"):
        load_config(p)
    with pytest.raises(SystemExit, match="malicious_min_confidence"):
        cli._cfg(argparse.Namespace(config=str(p), model=None, endpoint=None))


def test_bounds_are_inclusive():
    assert ReviewerConfig(malicious_min_confidence=0).malicious_min_confidence == 0
    assert ReviewerConfig(malicious_min_confidence=1.0).malicious_min_confidence == 1.0


# ---- execctx: setuptools-only sources are read only under a setuptools backend ----

def _import_line(ctx):
    return next(ln for ln in ctx.split("\n") if ln.startswith("import"))


def test_setuptools_tables_are_ignored_under_another_backend():
    pp = (b"[build-system]\nbuild-backend = 'hatchling.build'\n[project]\nname = 'acme'\n"
          b"[tool.setuptools]\npackages = []\npy-modules = []\n")
    line = _import_line(execctx.build({"pyproject.toml": pp, "acme/__init__.py": b""}))
    assert "packages=none;" not in line and "py-modules=none;" not in line
    assert "packages=auto-discovered: acme;" in line
    assert "py-modules=none in scanned files (hatchling.build may generate its own)" in line


def test_setup_cfg_is_ignored_under_an_in_tree_backend():
    pp = b"[build-system]\nbuild-backend = 'setuptools.build_meta'\nbackend-path = ['.']\n"
    line = _import_line(execctx.build({"pyproject.toml": pp, "setup.cfg": b"[options]\npackages =\n    \n"
                                       b"py_modules = only\n"}))
    g = "none in scanned files (in-tree backend setuptools.build_meta may generate its own)"
    assert f"packages=auto-discovered: {g};" in line and f"py-modules={g};" in line


def test_setuptools_tables_are_still_read_under_setuptools():
    pp = b"[build-system]\nbuild-backend = 'setuptools.build_meta'\n[tool.setuptools]\npackages = ['acme']\n"
    assert "packages=acme;" in _import_line(execctx.build({"pyproject.toml": pp}))


def test_math_nan_is_not_a_valid_threshold():
    with pytest.raises(ValueError):
        ReviewerConfig(malicious_min_confidence=math.nan)


# ---- fix round 1 ----

@pytest.mark.parametrize("key", ["runs_when", "attack_type", "recommended_action", "reasoning", "cited_hunk"])
@pytest.mark.parametrize("bad", [["build"], {"a": 1}])
def test_a_list_or_dict_value_falls_back_to_the_default(key, bad):
    v = _review(_full(**{key: bad}))
    assert v.classification == "malicious"
    assert (v.runs_when, v.attack_type, v.recommended_action) == (
        "unknown" if key == "runs_when" else "build", "none" if key == "attack_type" else "install-hook-rce",
        "report-to-pypi")
    if key in ("reasoning", "cited_hunk"):
        assert getattr(v, key) == ""


def test_a_non_string_value_on_a_malicious_verdict_still_alerts(tmp_path):
    cfg, conn, rid = _setup(tmp_path)
    d = _full(attack_type=["dropper"], recommended_action={"x": 1})
    rvw = reviewer.Reviewer(cfg, backend=_FakeBackend([json.dumps(d)]))
    orchestrator._review_escalated(cfg, conn, rvw, _diff(), _triage(), rid)
    assert [a["classification"] for a in _alerts(conn)] == ["malicious"]


def test_a_non_string_action_on_a_benign_verdict_is_monitor():
    assert _review(_full(classification="benign", recommended_action=["dismiss"])).recommended_action == "monitor"


def test_a_missing_confidence_escalates():
    be = _FakeBackend([json.dumps(_full(classification="benign", confidence="low")),
                       json.dumps(_full(classification="benign", confidence=0.9))], primary="sonnet", escalation="opus")
    v = reviewer.Reviewer(Config(), backend=be).review(_diff(), _triage())
    assert v.model == "opus" and v.confidence == 0.9 and not be.scripted


@pytest.mark.parametrize("files", [
    {"pyproject.toml": b"[build-system]\nbuild-backend = 'setuptools.build_meta'\nbackend-path = ['.']\n"},
    {"pyproject.toml": b"[build-system\nnot toml"},
])
def test_an_unread_setup_py_is_never_claimed_to_declare_none(files):
    files = {**files, "setup.py": b"from setuptools import setup\nsetup(packages=['acme'], py_modules=['m'])\n"}
    line = _import_line(execctx.build(files))
    assert execctx.NOT_LITERAL not in line and "none declared literally" not in line
    assert "may generate its own" in line


@pytest.mark.parametrize("key", ["reasoning", "cited_hunk", "attack_type", "runs_when", "urgent", "confidence"])
def test_an_explicit_null_takes_the_default(key):
    v = _review(_full(**{key: None}))
    assert v.classification == "malicious"
    assert v.reasoning is not None and v.cited_hunk is not None and v.attack_type is not None
    assert v.runs_when is not None and v.urgent in (True, False)


def test_a_malicious_verdict_with_null_reasoning_alerts_with_the_model_lines(tmp_path, capsys):
    cfg, conn, rid = _setup(tmp_path)
    rvw = reviewer.Reviewer(cfg, backend=_FakeBackend([json.dumps(_full(reasoning=None))]))
    orchestrator._review_escalated(cfg, conn, rvw, _diff(), _triage(), rid)
    out = capsys.readouterr().out
    assert "[DIFFWATCH] malicious" in out and "attack=install-hook-rce" in out and "model=m" in out


@pytest.mark.parametrize("raw, want", [(True, True), (False, False), ("false", False), ("true", False),
                                       (1, False), (None, False), ([True], False)])
def test_urgent_is_true_only_for_json_true(raw, want):
    assert _review(_full(urgent=raw)).urgent is want
