"""Spec F §3.2: what the model sees. Synthetic diffs only; nothing is executed."""
import pytest

from pydiffwatch import differ, reviewer
from pydiffwatch.models import ArtifactSet, Diff, FileDiff, FiredRule, Hunk, TriageResult


def _fd(path, lines, kind="modified"):
    return FileDiff(path, kind, [Hunk((0, 0), (0, len(lines)), list(lines), [])], "\n".join(lines) + "\n")


def _heads(text):
    return [ln for ln in text.split("\n") if ln.startswith("--- file: ")]


def test_the_header_shows_no_score():
    d = Diff("p", "1.1", False, [_fd("a.py", ["exec(x)"])], [])
    text = reviewer.build_review_input(d, TriageResult(77.0, [FiredRule("r", 77.0, "a.py", (1, 1))], True),
                                       max_chars=10_000)
    assert "triage_score" not in text and "77" not in text.split("untrusted_content_marker")[0]
    assert f"{reviewer._LOC_HEADING} a.py:1-1" in text              # the pointer stays; only the score is gone


def test_headings_carry_the_class_and_the_run_by():
    hook = FileDiff("_helper.py", "unchanged", [], "import os\n", run_by="setup.py")
    d = Diff("p", "1.1", False, [_fd("setup.py", ["import _helper"])], [], hook_targets=[hook],
             file_classes={"setup.py": "build", "_helper.py": "build"})
    text = reviewer.build_review_input(d, TriageResult(40.0, [FiredRule("r", 40.0, "setup.py", (1, 1))], True),
                                       max_chars=10_000)
    assert _heads(text) == ["--- file: setup.py (modified; class=build) ---",
                            "--- file: _helper.py (unchanged; class=build; run by setup.py) ---"]
    assert "@@ whole file, new L1-1" in text.split("_helper.py")[1]


def test_weighted_first_then_run_order_smallest_first():
    files = [_fd("pkg/big.py", ["y = 1"] * 50), _fd("pkg/small.py", ["y = 2"]), _fd("pkg/__init__.py", ["z = 3"]),
             _fd("setup.py", ["w = 4"] * 3), _fd("tests/t.py", ["t = 5"]), _fd("pkg/flagged.py", ["exec(x)"])]
    d = Diff("p", "1.1", False, files, [])
    tr = TriageResult(40.0, [FiredRule("r", 40.0, "pkg/flagged.py", (1, 1))], True)
    ranked, _, cut = reviewer._rank_files(d, tr)
    assert ranked == ["pkg/flagged.py", "setup.py", "pkg/__init__.py", "pkg/small.py", "pkg/big.py"]
    assert cut == []                                                   # tests/t.py is not-shipped: not selected


def test_churn_never_pushes_a_weighted_file_out():
    # Review Focus 3 (R2-1): 50 larger unweighted runnable files and one small weighted payload
    files = [_fd(f"pkg/m{i:02d}.py", [f"v{i} = {i}"] * 40) for i in range(50)] + [_fd("pkg/_boot.py", ["exec(x)"])]
    d = Diff("p", "1.1", False, files, [])
    tr = TriageResult(40.0, [FiredRule("r", 40.0, "pkg/_boot.py", (1, 1))], True)
    dropped = []
    text = reviewer.build_review_input(d, tr, max_chars=6_000, dropped=dropped)
    assert _heads(text)[0] == "--- file: pkg/_boot.py (modified; class=runtime-call) ---"
    assert "pkg/_boot.py" not in dropped and len(dropped) == 50 - (len(_heads(text)) - 1)


def test_a_file_that_does_not_fit_is_skipped_not_the_end_of_the_list():
    # pkg/__init__.py (import) ranks before pkg/c.py (runtime-call); it does not fit, and c.py still renders
    # 1,000 lines render ~8,200 chars as hunks (whole-file is over _WHOLE_FILE_MAX_CHARS), well over cap 5,000;
    # pkg/a.py (~75) and pkg/c.py (~75) fit beside the ~600-char header, blocks and reserves (plan review C1).
    files = [_fd("pkg/a.py", ["exec(x)"]), _fd("pkg/__init__.py", ["q = 1"] * 1_000), _fd("pkg/c.py", ["r = 1"])]
    d = Diff("p", "1.1", False, files, [])
    tr = TriageResult(40.0, [FiredRule("r", 40.0, "pkg/a.py", (1, 1))], True)
    assert reviewer._rank_files(d, tr)[0] == ["pkg/a.py", "pkg/__init__.py", "pkg/c.py"]
    dropped = []
    text = reviewer.build_review_input(d, tr, max_chars=5_000, dropped=dropped)
    assert [h.split(" ")[2] for h in _heads(text)] == ["pkg/a.py", "pkg/c.py"] and dropped == ["pkg/__init__.py"]
    assert reviewer._NOT_SHOWN_HEADING in text and "  pkg/__init__.py (import)" in text


def test_a_top_file_that_cannot_fit_still_raises_input_too_large():
    d = Diff("p", "1.1", False, [_fd("pkg/a.py", ["exec(x) " + "y" * 90] * 200), _fd("pkg/b.py", ["x = 1"])], [])
    tr = TriageResult(40.0, [FiredRule("r", 40.0, "pkg/a.py", (1, 200))], True)
    from pydiffwatch.config import Config, ReviewerConfig
    rvw = reviewer.Reviewer(Config(reviewer=ReviewerConfig(max_input_chars=4_000)), backend=object())
    with pytest.raises(reviewer.InputTooLarge) as e:
        rvw.prepare(d, tr)
    assert "--- file: pkg/a.py (modified; class=runtime-call) ---" in e.value.text
    assert len(e.value.text) <= e.value.needed and isinstance(e.value.shown, dict)


def test_an_oversized_unweighted_setup_py_lands_in_not_shown():
    # R2-3: no new too_large park for an unweighted build file
    d = Diff("p", "1.1", False, [_fd("pkg/a.py", ["exec(x)"]), _fd("setup.py", ["s = 1 " + "z" * 90] * 300)], [])
    tr = TriageResult(40.0, [FiredRule("r", 40.0, "pkg/a.py", (1, 1))], True)
    dropped = []
    text = reviewer.build_review_input(d, tr, max_chars=5_000, dropped=dropped)
    assert dropped == ["setup.py"] and "  setup.py (build)" in text


def test_a_weighted_data_file_cut_by_the_cap_is_in_dropped():
    # review C1
    d = Diff("p", "1.1", False, [_fd("pkg/a.py", ["exec(x)"]), _fd("pkg/cfg.json", ["k" * 90] * 200)], [])
    tr = TriageResult(60.0, [FiredRule("r", 40.0, "pkg/a.py", (1, 1)), FiredRule("r", 20.0, "pkg/cfg.json", (1, 1))],
                      True)
    dropped = []
    reviewer.build_review_input(d, tr, max_chars=4_000, dropped=dropped)
    assert dropped == ["pkg/cfg.json"]


def test_first_release_weighted_files_past_the_top_40_are_dropped():
    # R2-2
    files = [_fd(f"pkg/f{i:02d}.py", ["exec(x)"], kind="added") for i in range(45)]
    d = Diff("p", "1.0", True, files, [])
    tr = TriageResult(90.0, [FiredRule("r", 100.0 - i, f"pkg/f{i:02d}.py", (1, 1)) for i in range(45)], True)
    dropped = []
    reviewer.build_review_input(d, tr, max_chars=200_000, dropped=dropped)
    assert dropped == [f"pkg/f{i:02d}.py" for i in range(40, 45)]


def test_more_than_five_hook_targets_are_listed_not_shown():
    hooks = [FileDiff(f"h{i}.py", "unchanged", [], "x = 1\n", run_by="setup.py") for i in range(7)]
    d = Diff("p", "1.1", False, [_fd("setup.py", ["import h0"])], [], hook_targets=hooks)
    tr = TriageResult(40.0, [FiredRule("r", 40.0, "setup.py", (1, 1))], True)
    dropped = []
    text = reviewer.build_review_input(d, tr, max_chars=50_000, dropped=dropped)
    assert sum("(unchanged;" in h for h in _heads(text)) == 5 and dropped == ["h5.py", "h6.py"]


def test_unreadable_files_are_reported_and_listed():
    d = Diff("p", "1.1", False, [_fd("pkg/a.py", ["exec(x)"])], [{"path": "pkg/_c.so", "size": 9, "sha256": "h"}])
    unreadable = []
    text = reviewer.build_review_input(d, TriageResult(40.0, [FiredRule("r", 40.0, "pkg/a.py", (1, 1))], True),
                                       max_chars=10_000, unreadable=unreadable)
    assert unreadable == ["pkg/_c.so"] and reviewer._UNREADABLE_HEADING in text and "  pkg/_c.so: 9 bytes" in text


def test_a_dependency_only_fire_never_shows_unrelated_churn():
    # plan review C3: nothing weighted -> today's selection only; a/core.py is not shown, so no content -> UNREVIEWED
    d = Diff("p", "1.1", False, [_fd("a/core.py", ["x = 2"])], [],
             added_dep_findings=[{"name": "reqeusts", "reason": "typosquat", "target": "requests"}])
    tr = TriageResult(40.0, [FiredRule("dep-typosquat", 40.0, "reqeusts", (0, 0))], True)
    assert reviewer._rank_files(d, tr)[0] == []
    assert not reviewer._has_reviewable_content(reviewer.build_review_input(d, tr, max_chars=10_000))


def test_blocks_only_is_no_content():
    # review C2: an input with only blocks (a binary-only fire) is UNREVIEWED, never judged
    d = Diff("p", "1.1", False, [], [{"path": "pkg/_c.so", "size": 9, "sha256": "h"}], signals="releases on PyPI: 3")
    text = reviewer.build_review_input(d, TriageResult(40.0, [FiredRule("bin", 40.0, "pkg/_c.so", (0, 0))], True),
                                       max_chars=10_000)
    assert not reviewer._has_reviewable_content(text)


def test_prepare_stashes_what_was_not_seen():
    # pkg/b.py: 1,000 lines, ~8,200 chars as hunks, over cap 5,000 (plan review C1)
    d = Diff("p", "1.1", False, [_fd("pkg/a.py", ["exec(x)"]), _fd("pkg/b.py", ["q = 1"] * 1_000)],
             [{"path": "pkg/_c.so", "size": 9, "sha256": "h"}])
    from pydiffwatch.config import Config, ReviewerConfig
    rvw = reviewer.Reviewer(Config(reviewer=ReviewerConfig(max_input_chars=5_000)), backend=object())
    rvw.prepare(d, TriageResult(40.0, [FiredRule("r", 40.0, "pkg/a.py", (1, 1))], True))
    assert (rvw.dropped_files, rvw.unreadable, list(rvw.shown)) == (["pkg/b.py"], ["pkg/_c.so"], ["pkg/a.py"])


def test_the_not_shown_reserve_bounds_any_subset_of_long_paths():
    # 40 short small files rank before 10 long-named large ones: once the small ones render, the not-shown list's
    # first 40 lines are the long names, longer than the full list's first 40; the text never exceeds the cap
    files = ([_fd("pkg/a.py", ["exec(x)"])] + [_fd(f"pkg/s{i:02d}.py", ["v=1"]) for i in range(40)]
             + [_fd(f"pkg/{'l' * 400}{i:02d}.py", ["v = 1" * 40] * 30) for i in range(10)])
    d = Diff("p", "1.1", False, files, [])
    tr = TriageResult(40.0, [FiredRule("r", 40.0, "pkg/a.py", (1, 1))], True)
    base = len(reviewer.build_review_input(d, tr, max_chars=0))
    for cap in range(base, base + 12_000, 7):
        assert len(reviewer.build_review_input(d, tr, max_chars=cap)) <= cap, cap


def test_every_hook_target_is_shown_or_listed_whatever_its_class():
    # a hook target the class test would not select (not-shipped) is still shown, or listed as not shown
    hooks = [FileDiff("tests/helper.py", "unchanged", [], "x = 1\n", run_by="setup.py")] + [
        FileDiff(f"h{i}.py", "unchanged", [], "x = 1\n", run_by="setup.py") for i in range(6)]
    d = Diff("p", "1.1", False, [_fd("setup.py", ["import h0"])], [], hook_targets=hooks)
    tr = TriageResult(40.0, [FiredRule("r", 40.0, "setup.py", (1, 1))], True)
    dropped = []
    text = reviewer.build_review_input(d, tr, max_chars=50_000, dropped=dropped)
    shown = {h.split(" ")[2] for h in _heads(text)}
    assert all((h.path in shown) != (h.path in dropped) for h in hooks)
    assert "--- file: tests/helper.py (unchanged; class=not-shipped; run by setup.py) ---" in _heads(text)
    # and one that does not fit is listed, never silently skipped
    base = len(reviewer.build_review_input(d, tr, max_chars=0))
    for cap in range(base, base + 600, 5):
        dropped = []
        text = reviewer.build_review_input(d, tr, max_chars=cap, dropped=dropped)
        shown = {h.split(" ")[2] for h in _heads(text)}
        assert all((h.path in shown) != (h.path in dropped) for h in hooks), cap
