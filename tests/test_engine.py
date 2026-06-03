from pydiffwatch.engine import triage
from pydiffwatch.rules import validate_rule
from pydiffwatch.config import Config
from pydiffwatch.models import Diff, FileDiff, Hunk


def _code(path, added):
    return Diff("p", "1.1", False, [FileDiff(path, "modified",
        [Hunk((0, 0), (0, len(added)), added, [])], "\n".join(added))], [])


RULES = [validate_rule(r) for r in [
    {"id": "syntax", "applies_to": "code", "weight": 20, "location_scaled": True,
     "match": {"syntax_error": True}},
    {"id": "combo-decode-exec", "applies_to": "code", "weight": 45,
     "match": {"all": [{"bound_call": {"category": "decode"}}, {"bound_call": {"category": "exec"}}]}},
    {"id": "autoexec", "applies_to": "code", "weight": 45,
     "match": {"all": [{"location_at_least": 3.0}, {"any": [{"bound_call": {"category": "process"}},
               {"bound_call": {"category": "exec"}}, {"bound_call": {"category": "network"}}]}]}},
    {"id": "foreign", "applies_to": "binary", "weight": 25,
     "match": {"binary_reason": "foreign-language-source"}},
    {"id": "dep-typo", "applies_to": "dep", "weight": 40, "match": {"dep_reason": "typosquat"}},
]]


def test_combo_fires_and_escalates():
    r = triage(_code("m/__init__.py", ["import base64", "exec(base64.b64decode(B))"]), Config(), RULES)
    assert any(fr.rule == "combo-decode-exec" for fr in r.fired_rules) and r.escalate


def test_benign_scores_zero():
    r = triage(_code("m/x.py", ["import re, json", "re.compile(P)", "json.loads(B)"]), Config(), RULES)
    assert r.score == 0.0 and not r.escalate


def test_location_scaled_weight():
    r = triage(_code("setup.py", ["def (:::"]), Config(), RULES)   # syntax error in auto-exec location
    assert any(fr.rule == "syntax" and fr.weight == 60.0 for fr in r.fired_rules)   # 20 * 3.0


def test_binary_rule_accumulates_per_item():
    d = Diff("p", "1.1", False, [], [{"path": "a.php", "reason": "foreign-language-source"},
                                     {"path": "b.php", "reason": "foreign-language-source"}])
    r = triage(d, Config(), RULES)
    assert r.score == 50.0 and r.escalate


def test_dep_rule_fires_on_finding():
    d = Diff("p", "1.1", False, [], [], added_dep_findings=[{"name": "reqursts", "reason": "typosquat"}])
    r = triage(d, Config(), RULES)
    assert any(fr.rule == "dep-typo" for fr in r.fired_rules) and r.escalate
