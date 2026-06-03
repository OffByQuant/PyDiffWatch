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
