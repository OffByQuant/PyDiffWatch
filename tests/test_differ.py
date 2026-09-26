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
    lines = differ.render_signals(a.requires_dist_change, a.added_dep_findings, a.added_binaries, None).splitlines()
    added = [l for l in lines if l.startswith("added file")]
    assert added[0].startswith("added file p/big.py") and added[1].startswith("added file p/lib.so")
    assert "added file: … (+7 more)" in lines
