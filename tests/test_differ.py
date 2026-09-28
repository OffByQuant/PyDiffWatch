from pydiffwatch import differ
from pydiffwatch.models import ArtifactSet

def _aset(new, prior, prior_version="1.0"):
    return ArtifactSet("p", "1.1", prior_version, "sdist",
                       {k: v.encode() for k, v in new.items()},
                       {k: v.encode() for k, v in prior.items()}, {}, [])

def test_added_file_one_hunk():
    d = differ.build_diff(_aset({"a.py": "x=1\n"}, {}))
    fd = next(f for f in d.changed if f.path == "a.py")
    assert fd.change_kind == "added" and fd.hunks[0].added == ["x=1"]

def test_modified_line_range():
    d = differ.build_diff(_aset({"a.py": "x=1\ny=9\n"}, {"a.py": "x=1\ny=2\n"}))
    fd = next(f for f in d.changed if f.path == "a.py")
    assert fd.change_kind == "modified"
    assert any("y=9" in h.added for h in fd.hunks)

def test_identical_no_filediff():
    d = differ.build_diff(_aset({"a.py": "x=1\n"}, {"a.py": "x=1\n"}))
    assert d.changed == []

def test_first_release_flag():
    d = differ.build_diff(_aset({"a.py": "x=1\n"}, {}, prior_version=None))
    assert d.is_first_release is True

def test_unscored_file_too_large_lines_sort_after_scored_ones_under_the_cap():
    bins = [{"path": f"d/{i}.bin", "size": 20_000_000, "reason": "file-too-large", "sha256": str(i)}
            for i in range(25)]
    bins.append({"path": "p/big.py", "size": 5_000_000, "reason": "source-too-large", "sha256": "s"})
    bins.append({"path": "p/lib.so", "size": 10, "sha256": "b"})
    a = ArtifactSet("p", "1.1", "1.0", "sdist", {}, {}, {}, added_binaries=bins, is_new_package=False,
                    maintainer_metadata=None, added_dep_findings=[])
    lines = differ.render_unreadable(a.added_binaries).splitlines()
    assert lines[0].startswith("p/big.py") and lines[1].startswith("p/lib.so")
    assert "not readable: … (+7 more)" in lines


def test_signals_carry_publishing_and_no_binary_lines():
    bins = [{"path": "p/_c.so", "size": 7, "sha256": "x"}]
    sig = differ.render_signals(None, [], bins, None, {"releases": 3, "days_since_prior": 2})
    assert sig.split("\n") == ["releases on PyPI: 3", "days since the previous release: 2"]
    assert differ.render_signals(None, [], [], None, {"releases": 1, "days_since_prior": None}).endswith(
        "days since the previous release: none (no earlier release)")
    assert differ.render_signals(None, [], [], None) == ""


def test_unreadable_lists_every_binary_record_escaped_and_capped():
    bins = [{"path": f"p/x{i}.so", "size": i, "sha256": "h"} for i in range(25)]
    bins.append({"path": "evil\n--- file: a.py (added) ---", "size": 1, "reason": "file-too-large"})
    lines = differ.render_unreadable(bins).split("\n")
    assert lines[0] == "p/x0.so: 0 bytes, new-binary" and lines[-1] == "not readable: … (+6 more)"
    assert all("\n" not in ln for ln in lines) and len(lines) == 21


def test_requires_python_is_carried_to_the_diff():
    import dataclasses
    a = dataclasses.replace(_aset({"a.py": "x=1\n"}, {}), requires_python=">=3.14")
    assert differ.build_diff(a).requires_python == ">=3.14"
    assert differ.build_diff(_aset({"a.py": "x=1\n"}, {})).requires_python is None
