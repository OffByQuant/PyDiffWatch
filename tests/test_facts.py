from pydiffwatch.facts import build_facts
from pydiffwatch.models import Diff, FileDiff, Hunk


def _codediff(path, added):
    return Diff("p", "1.1", False, [FileDiff(path, "modified",
        [Hunk((0, 0), (0, len(added)), added, [])], "\n".join(added))], [])


def test_import_binding_categorizes_bound_calls():
    f = build_facts(_codediff("m/__init__.py", ["import base64", "exec(base64.b64decode(B))"])).files[0]
    assert "exec" in f.bound_categories and "decode" in f.bound_categories


def test_name_only_collisions_not_bound():
    f = build_facts(_codediff("m/x.py", ["import re, json", "re.compile(P)", "json.loads(B)"])).files[0]
    assert "exec" not in f.bound_categories and "decode" not in f.bound_categories


def test_location_weight_autoexec_and_tests():
    assert build_facts(_codediff("setup.py", ["x=1"])).files[0].location_weight == 3.0
    assert build_facts(_codediff("tests/t.py", ["x=1"])).files[0].location_weight == 0.2


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
