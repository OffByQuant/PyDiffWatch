def test_config_and_models_import():
    from pydiffwatch.config import Config
    from pydiffwatch import models
    cfg = Config()
    assert cfg.threshold_t == 40.0
    d = models.Diff(package="p", version="1", is_first_release=True, changed=[], added_binaries=[])
    assert d.is_first_release is True

def test_verdict_heuristic_shape_still_constructs():
    from pydiffwatch.models import Verdict
    v = Verdict("pkg", "1.0", "suspicious-heuristic", 42.0, [], False)
    assert v.confidence is None and v.reasoning is None and v.model is None

def test_verdict_llm_shape_carries_section7_fields():
    from pydiffwatch.models import Verdict
    v = Verdict("pkg", "1.0", "malicious", 80.0, [], True,
                confidence=0.92, attack_type="install-hook-rce",
                reasoning="setup.py downloads and execs a remote payload",
                cited_hunk="setup.py:12-19", recommended_action="report-to-pypi",
                model="claude-sonnet-4-6")
    assert v.classification == "malicious" and v.urgent is True
    assert v.attack_type == "install-hook-rce" and v.confidence == 0.92

def test_config_has_reviewer_defaults():
    from pydiffwatch.config import Config
    c = Config()
    # PyDiffWatch nests reviewer settings under cfg.reviewer (provider-agnostic ReviewerConfig).
    assert c.reviewer.provider == "openai"
    assert c.reviewer.structured_output == "json_schema"
    assert c.reviewer_enabled is True
    assert 0.0 < c.reviewer.opus_escalation_confidence <= 1.0
    assert c.reviewer.max_input_chars > 0 and c.reviewer.max_output_tokens > 0
