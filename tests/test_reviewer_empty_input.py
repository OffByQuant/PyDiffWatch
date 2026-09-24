"""An LLM that sees no package content must not be able to clear a release.

Triage can fire on signals that carry no reviewable text: an oversized file the
fetcher refused to read (binary-source-too-large), a new binary, or a maintainer
change. build_review_input then renders nothing between the markers, and a model
asked to judge nothing answers "benign — content is empty" (or invents a reason
from the package name). Such a release must skip the LLM and go to the human
adjudication queue instead.
"""
import json

from pydiffwatch import reviewer
from pydiffwatch.config import Config
from pydiffwatch.models import Diff, FileDiff, FiredRule, Hunk, TriageResult


class _FakeBackend:
    primary_model = "m"
    escalation_model = None

    def __init__(self):
        self.calls = 0

    def complete(self, **kw):
        self.calls += 1
        return json.dumps({"classification": "benign", "confidence": 1.0, "urgent": False,
                           "recommended_action": "dismiss", "attack_type": "none",
                           "cited_hunk": "None", "reasoning": "The provided package content is empty."})


def _review(diff, triage):
    be = _FakeBackend()
    v = reviewer.Reviewer(Config(), backend=be).review(diff, triage)
    return v, be


_OVERSIZED = TriageResult(40.0, [FiredRule("binary-source-too-large", 20.0, "pkg/a.py", (0, 0)),
                                 FiredRule("binary-source-too-large", 20.0, "pkg/b.py", (0, 0))], True)


def test_metadata_only_signals_skip_llm_and_queue_for_human():
    v, be = _review(Diff("p", "1.0.1", False, [], []), _OVERSIZED)
    assert be.calls == 0
    assert v.classification == "suspicious"          # routes to needs_adjudication
    assert v.confidence == 0.0
    assert "binary-source-too-large" in v.reasoning


def test_maintainer_only_signal_skips_llm():
    tr = TriageResult(40.0, [FiredRule("maintainer-set-change", 40.0, "<maintainers>", (0, 0))], True)
    v, be = _review(Diff("p", "1.0.1", False, [], []), tr)
    assert be.calls == 0
    assert v.classification == "suspicious"


def test_top_file_over_input_cap_raises_input_too_large():
    """A file larger than max_input_chars used to leave the model with no code at all. It must be
    parked for a larger-context model, not sent empty or partial."""
    huge = FileDiff("pkg/huge.py", "modified", [Hunk((0, 1), (0, 1), ["x" * 300_000], [])])
    tr = TriageResult(40.0, [FiredRule("primitives", 40.0, "pkg/huge.py", (1, 1))], True)
    be = _FakeBackend()
    try:
        reviewer.Reviewer(Config(), backend=be).review(Diff("p", "1.0.1", False, [huge], []), tr)
        raise AssertionError("expected InputTooLarge")
    except reviewer.InputTooLarge as e:
        assert e.cap == Config().reviewer.max_input_chars and e.needed > 300_000
        assert "x" * 300_000 in e.text
    assert be.calls == 0


def test_rendered_code_still_goes_to_llm():
    fd = FileDiff("setup.py", "modified", [Hunk((0, 1), (0, 1), ["exec(x)"], [])])
    v, be = _review(Diff("p", "1.0.1", False, [fd], []), _OVERSIZED)
    assert be.calls == 1
    assert v.classification == "benign"
