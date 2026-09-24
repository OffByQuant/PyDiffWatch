import ast

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
