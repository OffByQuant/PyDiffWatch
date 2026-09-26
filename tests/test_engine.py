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


def _many(n, line):
    return Diff("p", "1.1", False, [FileDiff(f"m/f{i}.py", "modified",
        [Hunk((0, 0), (0, 2), ["import os", line], [])], "import os\n" + line) for i in range(n)], [])


_PRIM = {"id": "prim", "applies_to": "code", "weight": 5, "location_scaled": True,
         "match": {"bound_call": {"category": "process"}}}


def test_max_total_caps_release_score_but_keeps_per_file_weights():
    capped = [validate_rule(dict(_PRIM, max_total=35))]
    r = triage(_many(20, "os.system(x)"), Config(), capped)
    fired = [fr for fr in r.fired_rules if fr.rule == "prim"]
    assert len(fired) == 20 and all(fr.weight == 5.0 for fr in fired)   # per-file entries intact
    assert r.score == 35.0 and not r.escalate


def test_absent_max_total_keeps_uncapped_sum():
    r = triage(_many(20, "os.system(x)"), Config(), [validate_rule(_PRIM)])
    assert r.score == 100.0 and r.escalate


def test_cap_is_per_rule_other_rules_still_add():
    rules = [validate_rule(dict(_PRIM, max_total=35)), RULES[3]]   # + foreign binary rule (25)
    d = _many(20, "os.system(x)")
    d.added_binaries.append({"path": "a.php", "reason": "foreign-language-source"})
    r = triage(d, Config(), rules)
    assert r.score == 60.0 and r.escalate


def test_score_caps_each_rule_at_its_max_total():
    from pydiffwatch import engine
    from pydiffwatch.models import FiredRule
    from pydiffwatch.rules import Rule
    rs = [Rule("primitives", "code", 20, {}, max_total=35), Rule("other", "code", 5, {})]
    fired = [FiredRule("primitives", 20.0, "a.py", (1, 1)), FiredRule("primitives", 20.0, "b.py", (1, 1)),
             FiredRule("other", 5.0, "a.py", (2, 2))]
    assert engine.score(fired, rs) == 40.0          # min(40, 35) + 5
    assert engine.score([FiredRule("unknown", 99.0, "a.py", (1, 1))], rs) == 0.0   # not in the ruleset


def test_triage_score_is_engine_score_of_its_fired_rules():
    import pathlib
    from pydiffwatch import engine, rules
    from pydiffwatch.config import Config
    from pydiffwatch.models import Diff, FileDiff, Hunk
    rs = rules.load_rules(pathlib.Path(__file__).parent.parent / "rules" / "community")
    src = "import os, base64\nexec(base64.b64decode('eA=='))\nos.system('id')\n"
    d = Diff("p", "1.1", False, [FileDiff("p/__init__.py", "modified",
                                          [Hunk((0, 0), (0, 3), src.splitlines(), [])], src)], [])
    tr = engine.triage(d, Config(), rs)
    assert tr.fired_rules and tr.score == engine.score(tr.fired_rules, rs)
