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
