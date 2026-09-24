"""Exact review-input accounting: len(text) <= max_chars for every cap, dropped == dropped_from_text(text), and a
zero-weight file that does not fit is skipped rather than hiding the smaller files ranked after it. Synthetic diffs
only; nothing is executed."""
import dataclasses

import pytest

from pydiffwatch import differ, reviewer
from pydiffwatch.models import ArtifactSet, Diff, FileDiff, FiredRule, Hunk, TriageResult


def _update(new, old, **kw):
    return differ.build_diff(ArtifactSet("p", "1.1", "1.0", "sdist", new, old, {}, [], **kw))


def _first(new):
    return differ.build_diff(ArtifactSet("p", "1.0", None, "sdist", new, {}, {}, []))


_SETUP_OLD = b"from setuptools import setup\nsetup(\n    name='p',\n    version='1.0',\n)\n"
_SETUP_NEW = b"from setuptools import setup\nimport os\nsetup(\n    name='p',\n    version='1.1',\n)\n"


# --- exact accounting sweep ------------------------------------------------------------------------------------

def _headings(text):
    return [ln for ln in text.split("\n") if ln.startswith("--- file: ")]


def _sweep(d, tr, span=6_000):
    base = len(reviewer.build_review_input(d, tr, max_chars=0))
    out = []
    for cap in range(base, base + span):
        dropped = []
        text = reviewer.build_review_input(d, tr, max_chars=cap, dropped=dropped)
        assert len(text) <= cap, (cap, len(text))
        assert reviewer.dropped_from_text(tr.fired_rules, text) == dropped, cap
        out.append((cap, text))
    # Tight, not just <=: at the cap where a file first fits exactly, only the note's unused reserve is left over.
    # A double-counted newline would leave 1 more char of slack on every such cap.
    slack = [cap - len(t) for cap, t in out if _headings(t) and t.endswith(reviewer.TRUNCATION_NOTE)]
    assert slack and min(slack) == reviewer._NOTE_RESERVE - len(reviewer.TRUNCATION_NOTE)
    return out


def test_two_file_sweep_never_exceeds_the_cap():
    """The controller's two-file case: `used` once omitted the "\\n" before the closing marker (+1 overrun)."""
    d = _update({"a.py": b"x=2\n" * 30, "b.py": b"y=2\n" * 30}, {"a.py": b"x=1\n", "b.py": b"y=1\n"})
    tr = TriageResult(50.0, [FiredRule("r", 30, "a.py", (1, 30)), FiredRule("r", 20, "b.py", (1, 30))], True)
    _sweep(d, tr, span=1_500)


def test_multi_file_sweep_update_with_whole_file_surface():
    new = {"setup.py": _SETUP_NEW, "pkg/__init__.py": b"import base64\nexec(base64.b64decode('eA=='))\n",
           "a.py": b"exec(1)\n" * 40, "b.py": b"exec(2)\n" * 5}
    old = {"setup.py": _SETUP_OLD, "pkg/__init__.py": b"\n", "a.py": b"\n", "b.py": b"\n"}
    d = _update(new, old, description="a package")
    d = dataclasses.replace(d, exec_context="build: setup.py", signals="dependency x: typosquat")
    tr = TriageResult(90.0, [FiredRule("r", 40, "setup.py", (2, 5)), FiredRule("r", 30, "pkg/__init__.py", (1, 2)),
                             FiredRule("r", 20, "a.py", (1, 40)), FiredRule("r", 10, "b.py", (1, 5))], True)
    results = _sweep(d, tr)
    assert "@@ whole file" in results[-1][1] and len(_headings(results[-1][1])) == 4


def test_a_large_zero_weight_file_does_not_hide_smaller_ones_after_it():
    """First release: a flagged file, then zero-weight files in rank order, the large one before the small."""
    new = {"a.py": b"exec(x)\n", "b_big.txt": b"B" * 3_000 + b"\n", "c_small.txt": b"c\n", "d_small.txt": b"d\n"}
    d = _first(new)
    tr = TriageResult(50.0, [FiredRule("r", 50.0, "a.py", (1, 1))], True)
    assert reviewer._rank_files(d, tr)[0] == ["a.py", "b_big.txt", "c_small.txt", "d_small.txt"]
    results = _sweep(d, tr)
    first = {p: next(cap for cap, t in results if f"--- file: {p} (added) ---" in _headings(t))
             for p in ("b_big.txt", "c_small.txt", "d_small.txt")}
    assert first["c_small.txt"] < first["d_small.txt"] < first["b_big.txt"]
    for cap, t in results:
        if "--- file: b_big.txt (added) ---" not in _headings(t):
            for p in ("c_small.txt", "d_small.txt"):   # the big one not fitting does not hide the small ones
                assert (f"--- file: {p} (added) ---" in _headings(t)) is (cap >= first[p]), (cap, p)
            assert t.endswith(reviewer.TRUNCATION_NOTE)


def test_a_dependency_only_fire_skips_a_large_build_file_but_shows_the_rest():
    new = {"setup.py": _SETUP_NEW, "pyproject.toml": b"[project]\n" + b"# pad\n" * 1_000, "setup.cfg": b"[metadata]\n"}
    old = {"setup.py": _SETUP_OLD, "pyproject.toml": b"\n", "setup.cfg": b"\n"}
    d = _update(new, old)
    tr = TriageResult(40.0, [FiredRule("dep", 40.0, "evilpkg", (0, 0))], True)
    results = _sweep(d, tr, span=8_000)
    shown = [set(_headings(t)) for _, t in results]
    assert any({"--- file: setup.py (modified) ---", "--- file: setup.cfg (modified) ---"} <= s
               and "--- file: pyproject.toml (modified) ---" not in s for s in shown)


def test_input_too_large_needed_renders_the_top_file():
    fd = FileDiff("a.py", "modified", [Hunk((0, 0), (0, 200), ["exec(x)"] * 200, [])])
    d = Diff("p", "1.1", False, [fd], [])
    tr = TriageResult(50.0, [FiredRule("r", 50.0, "a.py", (1, 200))], True)
    from pydiffwatch.config import Config, ReviewerConfig
    rvw = reviewer.Reviewer(Config(reviewer=ReviewerConfig(max_input_chars=500)), backend=object())
    with pytest.raises(reviewer.InputTooLarge) as e:
        rvw.prepare(d, tr)
    assert "--- file: a.py (modified) ---" in e.value.text and len(e.value.text) <= e.value.needed


# --- final review minor 1: context-block caps scale with the input cap --------------------------------------------

def test_a_small_cap_with_both_blocks_at_full_size_leaves_room_for_the_top_hunk():
    h = Hunk((0, 0), (0, 80), [f"exec(x)  # {i:02d} " + "y" * 80 for i in range(80)], [])
    d = Diff("p", "1.1", False, [FileDiff("a.py", "modified", [h])], [],
             exec_context="\n".join("e" * 2_000 for _ in range(10)), signals="\n".join("s" * 2_000 for _ in range(20)))
    tr = TriageResult(40.0, [FiredRule("r", 40.0, "a.py", (1, 80))], True)
    cap = 12_000
    dropped = []
    text = reviewer.build_review_input(d, tr, max_chars=cap, dropped=dropped)
    assert "--- file: a.py" in text and dropped == [] and not text.endswith(reviewer.TRUNCATION_NOTE)
    assert len(text) <= cap and reviewer.dropped_from_text(tr.fired_rules, text) == dropped
    assert text.count("e" * 100) and len(text.split(reviewer._EXEC_HEADING, 1)[1].split("--- ", 1)[0]) <= cap // 8


@pytest.mark.parametrize("cap", [0, 1_000, 8_000, 9_600, 16_000, 40_000, 200_000])
def test_scaled_block_caps_keep_accounting_exact(cap):
    h = Hunk((0, 0), (0, 3), ["exec(x)"] * 3, [])
    d = Diff("p", "1.1", False, [FileDiff("a.py", "modified", [h])], [],
             exec_context="\n".join("\x00" * 900 for _ in range(10)), signals="\n".join("s" * 900 for _ in range(45)))
    tr = TriageResult(40.0, [FiredRule("r", 40.0, "a.py", (1, 3))], True)
    dropped = []
    text = reviewer.build_review_input(d, tr, max_chars=max(cap, 1), dropped=dropped)
    assert reviewer.dropped_from_text(tr.fired_rules, text) == dropped
    if "--- file: a.py" in text:
        assert len(text) <= cap


# --- final review minor 4: a cut context line always keeps its "  " prefix -----------------------------------------

@pytest.mark.parametrize("cap", [1, 30, 60, 200])
def test_a_cut_context_line_keeps_its_indent(cap):
    block = reviewer._render_block("--- h ---", "\n".join("z" * 300 for _ in range(5)), cap)
    assert all(ln.startswith("  ") for ln in block.split("\n")[1:])


def test_the_block_floor_fits_the_largest_signals_block_with_every_cut_line_marked():
    for heading, n in ((reviewer._SIG_HEADING, 45), (reviewer._EXEC_HEADING, 10)):
        block = reviewer._render_block(heading, "\n".join("q" * 500 for _ in range(n)), reviewer._BLOCK_MIN_CHARS)
        assert len(block) <= reviewer._BLOCK_MIN_CHARS
        assert all(ln.startswith("  ") and ln.endswith(reviewer._EXEC_TRUNCATED) for ln in block.split("\n")[1:])


# --- residual R1: the text stored with InputTooLarge always contains the top file -----------------------------------

def _big_blocks_diff(hunk_chars):
    n = max(1, hunk_chars // 100)
    h = Hunk((0, 0), (0, n), [f"exec(x)  # {i:05d} " + "y" * 82 for i in range(n)], [])
    d = Diff("p", "1.1", False, [FileDiff("a.py", "modified", [h])], [],
             exec_context="\n".join("e" * 2_000 for _ in range(10)), signals="\n".join("s" * 2_000 for _ in range(20)))
    return d, TriageResult(40.0, [FiredRule("r", 40.0, "a.py", (1, n))], True)


def _too_large(d, tr, cap):
    from pydiffwatch.config import Config, ReviewerConfig
    rvw = reviewer.Reviewer(Config(reviewer=ReviewerConfig(max_input_chars=cap)), backend=object())
    with pytest.raises(reviewer.InputTooLarge) as e:
        rvw.prepare(d, tr)
    return e.value


def test_input_too_large_at_12k_with_full_blocks_stores_the_top_file():
    d, tr = _big_blocks_diff(10_000)
    e = _too_large(d, tr, 12_000)
    assert reviewer._has_reviewable_content(e.text) and "--- file: a.py (modified) ---" in e.text
    assert len(e.text) <= e.needed and reviewer.dropped_from_text(tr.fired_rules, e.text) == []


@pytest.mark.parametrize("cap", [8_000, 12_000, 16_000, 24_000])
@pytest.mark.parametrize("hunk", [5_000, 10_000, 20_000, 30_000])
def test_input_too_large_sweep_always_stores_reviewable_text(cap, hunk):
    d, tr = _big_blocks_diff(hunk)
    from pydiffwatch.config import Config, ReviewerConfig
    rvw = reviewer.Reviewer(Config(reviewer=ReviewerConfig(max_input_chars=cap)), backend=object())
    try:
        rvw.prepare(d, tr)
        return                                           # it fit at this cap: nothing is stored
    except reviewer.InputTooLarge as e:
        assert reviewer._has_reviewable_content(e.text), (cap, hunk, e.needed, len(e.text))
        assert "--- file: a.py (modified) ---" in e.text and len(e.text) <= e.needed
        assert reviewer.dropped_from_text(tr.fired_rules, e.text) == []
