import ast

import pytest

from pydiffwatch.facts import build_facts
from pydiffwatch.models import Diff, FileDiff, Hunk


def _codediff(path, added):
    return Diff("p", "1.1", False, [FileDiff(path, "modified",
        [Hunk((0, 0), (0, len(added)), added, [])], "\n".join(added))], [])


def _wholefile(path, full):
    added = full.splitlines()
    return Diff("p", "1.1", False, [FileDiff(path, "modified",
        [Hunk((0, 0), (0, len(added)), added, [])], full)], [])


def test_import_binding_categorizes_bound_calls():
    f = build_facts(_codediff("m/__init__.py", ["import base64", "exec(base64.b64decode(B))"])).files[0]
    assert "exec" in f.bound_categories and "decode" in f.bound_categories


def test_name_only_collisions_not_bound():
    f = build_facts(_codediff("m/x.py", ["import re, json", "re.compile(P)", "json.loads(B)"])).files[0]
    assert "exec" not in f.bound_categories and "decode" not in f.bound_categories


def test_location_weight_autoexec_and_tests():
    assert build_facts(_codediff("setup.py", ["x=1"])).files[0].location_weight == 3.0
    assert build_facts(_codediff("tests/t.py", ["x=1"])).files[0].location_weight == 0.2


def test_autoexec_categories_excludes_method_body():
    # aiops-ml shape: exec inside a method only runs when the package's runtime calls it -> NOT import
    # time. It still counts as a bound category (corroboration/combos), but NOT as an autoexec category.
    full = ("import base64\n"
            "class Algo:\n"
            "    def on_transfer(self, p_code):\n"
            "        s = base64.b64decode(p_code)\n"
            "        exec(s)\n")
    f = build_facts(_wholefile("pkg/__init__.py", full)).files[0]
    assert "exec" in f.bound_categories and "decode" in f.bound_categories
    assert "exec" not in f.autoexec_categories and "decode" not in f.autoexec_categories


def test_autoexec_categories_includes_module_top_level():
    f = build_facts(_codediff("pkg/__init__.py", ["import os", "os.system('id')"])).files[0]
    assert "process" in f.autoexec_categories


def test_autoexec_categories_one_hop_into_called_helper():
    full = ("import os\n\n"
            "def _boot():\n"
            "    os.system('id')\n\n"
            "_boot()\n")
    f = build_facts(_wholefile("pkg/__init__.py", full)).files[0]
    assert "process" in f.autoexec_categories


def test_blob_present_on_long_b64():
    f = build_facts(_codediff("m/d.py", ['D="' + "QABZ" * 40 + '"'])).files[0]
    assert f.blob_present is True


def test_syntax_error_fact():
    assert build_facts(_codediff("setup.py", ["def (:::"])).files[0].syntax_error is True


def test_from_import_binds_bare_name():
    f = build_facts(_codediff("setup.py", ["from os import system", "system('id')"])).files[0]
    assert "process" in f.bound_categories


def test_binary_reason_normalized_new_binary():
    d = Diff("p", "1.1", False, [], [{"path": "x.so", "sha256": "abc"}])
    assert build_facts(d).binaries[0]["reason"] == "new-binary"


def test_binary_reason_preserved_when_present():
    d = Diff("p", "1.1", False, [], [{"path": "a.php", "reason": "foreign-language-source"}])
    assert build_facts(d).binaries[0]["reason"] == "foreign-language-source"


def test_maintainer_changed():
    d = Diff("p", "1.1", False, [], [])
    ctx = {"current": {"roles": ["a", "b"]}, "prior": {"roles": ["a"]}}
    assert build_facts(d, ctx).maintainer_changed is True
    assert build_facts(d, {"current": {"roles": ["a"]}, "prior": {"roles": ["a"]}}).maintainer_changed is False


def test_source_that_crashes_the_parser_is_unparseable_not_a_crash():
    # Final review: ast.parse raises RecursionError on a long attribute chain (~400 KB, under the source cap),
    # which escaped the SyntaxError handler and failed the release deterministically, pinning the cursor.
    f = build_facts(_wholefile("m/x.py", "a" + ".b" * 200_000)).files[0]
    assert f.syntax_error is True


def test_parser_memory_and_value_errors_are_unparseable(monkeypatch):
    from pydiffwatch import facts
    for exc in (MemoryError(), ValueError("source code string cannot contain null bytes")):
        def boom(*a, exc=exc, **k):
            raise exc
        monkeypatch.setattr(facts.ast, "parse", boom)
        assert build_facts(_wholefile("m/x.py", "x = 1")).files[0].syntax_error is True


def test_post_parse_recursion_crash_marks_unparseable_not_a_crash():
    # ast.parse succeeds on a wide (not deep) expression, but the old recursive
    # _calls_outside_funcs walk blew the recursion limit on it -> RecursionError escaped build_facts.
    src = "x = " + "+".join(["1"] * 5000)
    f = build_facts(_wholefile("m/__init__.py", src)).files[0]
    assert f.syntax_error is True


def test_post_parse_recursion_crash_marks_unparseable_non_init_file():
    src = "x = " + "+".join(["1"] * 5000)
    f = build_facts(_wholefile("pkg/util.py", src)).files[0]
    assert f.syntax_error is True


def test_generated_shape_under_depth_cap_is_not_flagged():
    # A ~300-term chain (generated-code shape, e.g. a wide string-builder) is well under _MAX_AST_DEPTH
    # and must not be treated as suspicious on depth alone.
    src = "x = " + "+".join(["1"] * 300)
    f = build_facts(_wholefile("pkg/util.py", src)).files[0]
    assert f.syntax_error is False


def test_depth_flag_is_additive_not_a_replacement_for_scanning():
    # CRITICAL fix: the depth check must never short-circuit the actual extraction. A file with both a
    # real decode->exec loader AND a deep pad must still report the loader's categories/names -- the
    # depth flag only adds syntax_error=True, it does not empty out everything else.
    pad = "+".join(["1"] * 5000)
    src = f"import base64\npad = {pad}\nexec(base64.b64decode(d))\n"
    f = build_facts(_wholefile("pkg/util.py", src)).files[0]
    assert f.syntax_error is True
    assert "exec" in f.bound_categories and "decode" in f.bound_categories


def test_importtime_call_ids_iterative_matches_recursive_on_normal_code():
    # Equivalence check for the iterative rewrite: nested functions, a class, and top-level calls.
    from pydiffwatch.facts import _importtime_call_ids

    _FUNC_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)

    def _calls_outside_funcs_recursive(node):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, _FUNC_NODES):
                continue
            if isinstance(child, ast.Call):
                yield child
            yield from _calls_outside_funcs_recursive(child)

    def _importtime_call_ids_recursive(tree):
        module_funcs = {n.name: n for n in tree.body
                        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        importtime = list(_calls_outside_funcs_recursive(tree))
        ids = {id(c) for c in importtime}
        for c in importtime:
            f = c.func
            if isinstance(f, ast.Name) and f.id in module_funcs:
                for sub in ast.walk(module_funcs[f.id]):
                    if isinstance(sub, ast.Call):
                        ids.add(id(sub))
        return ids

    src = (
        "import os\n"
        "top_level_call()\n"
        "def helper():\n"
        "    inner_call()\n"
        "    def nested():\n"
        "        deep_call()\n"
        "    return nested\n"
        "class C:\n"
        "    class_body_call()\n"
        "    def method(self):\n"
        "        method_call()\n"
        "lam = lambda: lambda_call()\n"
        "helper()\n"
    )
    tree_a = ast.parse(src)
    tree_b = ast.parse(src)
    # Compare by (lineno, col_offset, func-name-ish) since id() differs between the two trees.
    def _signature(tree, ids):
        sigs = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and id(node) in ids:
                f = node.func
                name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
                sigs.add((node.lineno, node.col_offset, name))
        return sigs

    expected = _signature(tree_a, _importtime_call_ids_recursive(tree_a))
    actual = _signature(tree_b, _importtime_call_ids(tree_b))
    assert actual == expected
    assert expected == {
        (2, 0, "top_level_call"),
        (4, 4, "inner_call"), (6, 8, "deep_call"),     # pulled in by the one-hop expansion of helper()
        (9, 4, "class_body_call"),
        (13, 0, "helper"),                             # lambda body itself is never walked (not module_funcs)
    }


def test_pth_import_line_yields_process_autoexec():
    d = _codediff("evil.pth", ["import os;os.system('id')"])
    f = build_facts(d).files[0]
    assert "process" in f.autoexec_categories
    assert f.location_weight == 3.0


def test_pth_path_only_lines_yield_nothing():
    d = _codediff("normal.pth", ["../site-packages", "/opt/pkg/lib"])
    f = build_facts(d).files[0]
    assert f.bound_categories == frozenset() and f.autoexec_categories == frozenset()


def test_pth_deep_import_line_does_not_crash():
    pad = "+".join(["1"] * 5000)
    d = _codediff("evil.pth", [f"import os;os.system('id' + str({pad}))"])
    f = build_facts(d).files[0]   # must not raise (RecursionError guarded)
    assert "process" in f.autoexec_categories


def test_pth_bom_prefixed_import_line_yields_process_autoexec():
    from pydiffwatch.models import Diff, FileDiff, Hunk
    added = ["import os;os.system('id')"]
    new_text = "﻿" + "\n".join(added)
    d = Diff("p", "1.1", False, [FileDiff("evil.pth", "added",
        [Hunk((0, 0), (0, 1), added, [])], new_text)], [])
    f = build_facts(d).files[0]
    assert "process" in f.autoexec_categories


def test_pth_invalid_utf8_later_on_import_line_does_not_crash():
    from pydiffwatch.models import Diff, FileDiff, Hunk
    new_text = "import os;os.system('id�')"   # replacement char, as errors=\"replace\" decode would yield
    added = [new_text]
    d = Diff("p", "1.1", False, [FileDiff("evil.pth", "added",
        [Hunk((0, 0), (0, 1), added, [])], new_text)], [])
    f = build_facts(d).files[0]   # must not raise
    assert "process" in f.autoexec_categories


@pytest.mark.parametrize("full", [
    "import os\n\n@deco(os.system('x'))\ndef f():\n    pass\n",                     # decorator argument
    "import os\n\ndef f(x=os.system('y')):\n    pass\n",                          # default argument
    "import os\n\ndef f(*, x=os.system('y')):\n    pass\n",                       # keyword-only default
    "import os\n\ndef f(x: os.system('y')):\n    pass\n",                         # argument annotation
    "import os\n\ndef f() -> os.system('y'):\n    pass\n",                        # return annotation
    "import os\n\ng = lambda x=os.system('y'): x\n",                             # lambda default
])
def test_a_call_in_a_function_header_runs_at_import_time(full):
    # Decorators, defaults and annotations are evaluated when the `def` runs, i.e. at import; only the body waits.
    f = build_facts(_wholefile("pkg/__init__.py", full)).files[0]
    assert "process" in f.autoexec_categories


def test_a_call_in_a_function_body_still_does_not_run_at_import_time():
    full = "import os\n\n@staticmethod\ndef f(x=1) -> int:\n    os.system('y')\n"
    assert "process" not in build_facts(_wholefile("pkg/__init__.py", full)).files[0].autoexec_categories


# ---- PR D: false signals removed ----

def test_conftest_follows_the_path_rules():
    from pydiffwatch.facts import classify_location
    assert classify_location("conftest.py") == 1.0
    assert classify_location("tests/conftest.py") == 0.2
    for p in ("pkg/__init__.py", "setup.py", "x.pth"):
        assert classify_location(p) == 3.0


def test_a_pyx_that_fails_to_parse_is_not_a_syntax_error():
    assert build_facts(_wholefile("m.pyx", "cdef int x = 1\n")).files[0].syntax_error is False
    assert build_facts(_wholefile("M.PYX", "cdef int x = 1\n")).files[0].syntax_error is False
    assert build_facts(_wholefile("m.py", "cdef int x = 1\n")).files[0].syntax_error is True


def test_a_pyx_that_parses_is_scanned():
    f = build_facts(_wholefile("m.pyx", "import subprocess\nsubprocess.run(c)\n")).files[0]
    assert "process" in f.bound_categories


def test_a_bom_file_parses_and_is_scanned():
    f = build_facts(_wholefile("m.py", "\ufeffimport os\nos.system(c)\n")).files[0]
    assert f.syntax_error is False and "process" in f.bound_categories
    assert build_facts(_wholefile("m.py", "\ufeffdef (:\n")).files[0].syntax_error is True


def test_codecs_decode_binds_as_decode_and_bytes_decode_does_not():
    assert "decode" in build_facts(_wholefile("m.py", 'import codecs\ncodecs.decode(s, "rot13")\n')).files[0].bound_categories
    assert "decode" not in build_facts(_wholefile("m.py", "s.decode()\n")).files[0].bound_categories


_PROSE = "- :mod:`open61850.goose`: GOOSE PDUs and frames (IEC 61850-8-1)."   # 64 chars, entropy 4.78


def test_docstring_prose_is_not_a_blob():
    assert build_facts(_wholefile("m.py", f'"""\n{_PROSE}\n"""\n')).files[0].blob_present is False
    assert build_facts(_wholefile("m.py", f'x = """\n{_PROSE}\n"""\n')).files[0].blob_present is True
    cls = f'class C:\n    """\n    {_PROSE}\n    """\n'
    fn = f'def f():\n    """\n    {_PROSE}\n    """\n'
    assert build_facts(_wholefile("m.py", cls)).files[0].blob_present is False
    assert build_facts(_wholefile("m.py", fn)).files[0].blob_present is False


def test_a_long_base64_run_in_a_docstring_is_still_a_blob():
    assert build_facts(_wholefile("m.py", '"""\n' + "QABZ" * 40 + '\n"""\n')).files[0].blob_present is True


def test_a_long_docstring_line_is_not_a_blob_but_a_long_code_line_is():
    assert build_facts(_wholefile("m.py", '"""\n' + "word " * 101 + '\n"""\n')).files[0].blob_present is False
    assert build_facts(_wholefile("m.py", "x = 1  # " + "word " * 101 + "\n")).files[0].blob_present is True


def test_an_encoded_url_code_line_is_still_a_blob():
    # spec §6: dately's hidden-URL line is code, not a docstring (64 chars, entropy 5.02)
    line = 'url_unformatted = "aHR0cHM6Ly9leGFtcGxlLmludmFsaWQvZGF0YS5qc29u"'
    assert build_facts(_codediff("pkg/_connect.py", [line])).files[0].blob_present is True


def test_the_docstring_mask_follows_line_numbers_across_hunks():
    # Review Focus 4: the file's added lines are in two hunks; the docstring is in the second one.
    full = f'x = 1\ny = 2\ndef f():\n    """\n    {_PROSE}\n    """\n'
    lines = full.splitlines()
    fd = FileDiff("m.py", "modified", [Hunk((0, 0), (0, 1), lines[0:1], []),
                                       Hunk((1, 1), (2, 6), lines[2:6], [])], full)
    assert build_facts(Diff("p", "1.1", False, [fd], [])).files[0].blob_present is False
    code = full.replace('    """\n', "    s = '''\n", 1).replace('    """\n', "    '''\n", 1)
    lines = code.splitlines()
    fd = FileDiff("m.py", "modified", [Hunk((0, 0), (0, 1), lines[0:1], []),
                                       Hunk((1, 1), (2, 6), lines[2:6], [])], code)
    assert build_facts(Diff("p", "1.1", False, [fd], [])).files[0].blob_present is True


# ---- PR D: interpreter skew ----
from pydiffwatch import facts as facts_mod

_UNPARSEABLE = "def f(:\n    pass\n"    # Ruling P1: fails on every CPython, so the tests hold on 3.14+


def _skew(path, rp, runtime, monkeypatch):
    monkeypatch.setattr(facts_mod, "RUNTIME", runtime)
    added = _UNPARSEABLE.splitlines()
    d = Diff("p", "1.1", False, [FileDiff(path, "modified", [Hunk((0, 0), (0, len(added)), added, [])],
                                          _UNPARSEABLE)], [], requires_python=rp)
    f = build_facts(d).files[0]
    return f.syntax_error, f.newer_syntax


@pytest.mark.parametrize("path,rp,runtime,expected", [
    ("pkg/m.py", ">=3.14", (3, 13), (False, True)),
    ("pkg/m.py", "<4.0,>=3.14", (3, 13), (False, True)),
    ("pkg/m.py", "~=3.14", (3, 13), (False, True)),
    ("pkg/m.py", "==3.14.*", (3, 13), (False, True)),
    ("tests/test_m.py", ">=3.14", (3, 13), (False, True)),
    ("pkg/m.py", ">=3.9", (3, 13), (True, False)),
    ("pkg/m.py", None, (3, 13), (True, False)),
    ("pkg/m.py", ">3.13", (3, 13), (True, False)),
    ("pkg/m.py", "garbage", (3, 13), (True, False)),
    ("pkg/__init__.py", ">=3.14", (3, 13), (True, False)),
    ("setup.py", ">=3.14", (3, 13), (True, False)),
    ("pkg/m.py", ">=3.14", (3, 14), (True, False)),
])
def test_skew_moves_only_non_autoexec_files_under_a_newer_floor(path, rp, runtime, expected, monkeypatch):
    assert _skew(path, rp, runtime, monkeypatch) == expected


def test_requires_floor():
    rf = facts_mod.requires_floor
    assert rf(">=3.14") == (3, 14) and rf("~=3.14") == (3, 14) and rf("==3.14.*") == (3, 14)
    assert rf(">=3.9, <4") == (3, 9) and rf(">=3.10,>=3.12") == (3, 12) and rf(">=3") == (3, 0)
    assert rf(None) is None and rf("") is None and rf(">3.13") is None and rf("garbage") is None


def test_a_huge_version_number_is_no_floor():
    # Review Focus 1 (Ruling P4): int() of a 5,000-digit string raises on CPython >= 3.11; the clause never counts.
    assert facts_mod.requires_floor(">=3." + "9" * 5000) is None


def test_a_pyx_under_a_newer_floor_is_neither(monkeypatch):
    # Review Focus 5: Cython is not Python, so no syntax reading and no skew reading.
    assert _skew("pkg/m.pyx", ">=3.14", (3, 13), monkeypatch) == (False, False)
