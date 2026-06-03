import logging
from pydiffwatch.rules import load_rules, evaluate, validate_rule
from pydiffwatch.facts import FileFacts


def _code(cats=(), names=(), mods=(), blob=False, syn=False, loc=1.0, added=()):
    return FileFacts("m.py", (1, 1), loc, frozenset(cats), frozenset(names),
                     frozenset(mods), blob, syn, tuple(added))


def test_valid_combo_rule_parses():
    r = validate_rule({"id": "c", "applies_to": "code", "weight": 45,
                       "match": {"all": [{"bound_call": {"category": "decode"}},
                                         {"bound_call": {"category": "exec"}}]}})
    assert r is not None and r.id == "c" and r.weight == 45.0


def test_matcher_all_any_not():
    m = {"all": [{"bound_call": {"category": "decode"}}, {"not": {"syntax_error": True}}]}
    assert evaluate(m, _code(cats=("decode",))) is True
    assert evaluate(m, _code(cats=("decode",), syn=True)) is False


def test_bound_call_category_list():
    m = {"bound_call": {"category": ["process", "exec"]}}
    assert evaluate(m, _code(cats=("process",))) is True
    assert evaluate(m, _code(cats=("network",))) is False


def test_bound_call_name():
    assert evaluate({"bound_call": {"name": "system"}}, _code(names=("system",))) is True
    assert evaluate({"bound_call": {"name": "system"}}, _code(names=("get",))) is False


def test_location_at_least():
    assert evaluate({"location_at_least": 3.0}, _code(loc=3.0)) is True
    assert evaluate({"location_at_least": 3.0}, _code(loc=1.0)) is False


def test_regex_over_added_lines():
    assert evaluate({"regex": {"pattern": r"curl .*\| ?sh"}}, _code(added=("curl x|sh",))) is True


def test_unknown_predicate_rule_rejected(caplog):
    with caplog.at_level(logging.WARNING):
        assert validate_rule({"id": "bad", "applies_to": "code", "weight": 1,
                              "match": {"danger": {"x": 1}}}) is None
    assert "bad" in caplog.text


def test_wrong_scope_predicate_rejected():
    assert validate_rule({"id": "x", "applies_to": "code", "weight": 1,
                          "match": {"dep_reason": "typosquat"}}) is None


def test_bad_enum_value_rejected():
    assert validate_rule({"id": "x", "applies_to": "code", "weight": 1,
                          "match": {"bound_call": {"category": "rootkit"}}}) is None


def test_arbitrary_text_in_match_rejected():
    assert validate_rule({"id": "x", "applies_to": "code", "weight": 1,
                          "match": "__import__('os').system('id')"}) is None


def test_missing_required_field_rejected():
    assert validate_rule({"applies_to": "code", "weight": 1, "match": {"syntax_error": True}}) is None


def test_bad_scope_rejected():
    assert validate_rule({"id": "x", "applies_to": "galaxy", "weight": 1,
                          "match": {"syntax_error": True}}) is None


def test_load_rules_drops_bad_keeps_good(tmp_path, caplog):
    (tmp_path / "ok.yaml").write_text(
        "- id: ok\n  applies_to: code\n  weight: 20\n  match: {syntax_error: true}\n")
    (tmp_path / "bad.yaml").write_text(
        "- id: bad\n  applies_to: code\n  weight: 1\n  match: {danger: {x: 1}}\n")
    with caplog.at_level(logging.WARNING):
        rules = load_rules(tmp_path)
    ids = {r.id for r in rules}
    assert "ok" in ids and "bad" not in ids


def test_unhashable_enum_arg_rejected_not_crash():
    # binary_reason/dep_reason expect a string enum; an unhashable list/dict must be REJECTED, never
    # raise (the `in` membership test on a set would TypeError on an unhashable arg).
    assert validate_rule({"id": "x", "applies_to": "binary", "weight": 1,
                          "match": {"binary_reason": ["a", "b"]}}) is None
    assert validate_rule({"id": "y", "applies_to": "dep", "weight": 1,
                          "match": {"dep_reason": {"k": "v"}}}) is None


def test_load_rules_survives_crashy_rule(tmp_path):
    # A rule whose predicate arg would crash validation must be dropped, not abort the whole load
    # (fail-closed). The good rule in the same dir must still load.
    (tmp_path / "ok.yaml").write_text(
        "- id: ok\n  applies_to: code\n  weight: 1\n  match: {syntax_error: true}\n")
    (tmp_path / "crash.yaml").write_text(
        "- id: crash\n  applies_to: binary\n  weight: 1\n  match: {binary_reason: [a, b]}\n")
    rules = load_rules(tmp_path)   # must NOT raise
    ids = {r.id for r in rules}
    assert "ok" in ids and "crash" not in ids


def test_oversized_regex_pattern_rejected():
    # An absurdly long community regex is rejected at load (bounds memory; reduces ReDoS surface).
    assert validate_rule({"id": "x", "applies_to": "code", "weight": 1,
                          "match": {"regex": {"pattern": "a" * 5000}}}) is None


def test_load_rules_dedupes_ids(tmp_path):
    (tmp_path / "a.yaml").write_text(
        "- id: dup\n  applies_to: code\n  weight: 1\n  match: {syntax_error: true}\n"
        "- id: dup\n  applies_to: code\n  weight: 2\n  match: {syntax_error: true}\n")
    rules = load_rules(tmp_path)
    assert sum(1 for r in rules if r.id == "dup") == 1
