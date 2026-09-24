"""Oversized sources, binaries and foreign-language files are signals only when this release adds or
changes them. A package that republishes the same oversized/binary/foreign files release after release
must not escalate each one to a human."""
from pydiffwatch import fetcher
from pydiffwatch.config import Config
from pydiffwatch.models import NewRelease
from tests.fixtures.build_fixtures import make_sdist

_BIG = b"# bundle\n" + b"x = 1  # filler\n" * 200000   # over max_source_file_bytes (1 MB)


def _meta(pkg):
    return {"releases": {
        "1.0": [{"packagetype": "sdist", "url": f"mock://{pkg}/1.0",
                 "upload_time_iso_8601": "2026-01-01T00:00:00Z"}],
        "1.1": [{"packagetype": "sdist", "url": f"mock://{pkg}/1.1",
                 "upload_time_iso_8601": "2026-02-01T00:00:00Z"}],
    }}


def _fetch(monkeypatch, old, new, prior_fails=False):
    monkeypatch.setattr(fetcher, "_package_json", lambda p, cfg: _meta("acme"))
    blobs = {"mock://acme/1.0": make_sdist(old), "mock://acme/1.1": make_sdist(new)}

    def download(url, cfg):
        if prior_fails and url.endswith("/1.0"):
            raise TimeoutError("download took longer than 120s")
        return blobs[url]
    monkeypatch.setattr(fetcher, "_download", download)
    art = fetcher.fetch_artifacts(Config(), NewRelease("acme", "1.1", 2))
    return sorted(b["path"] for b in art.added_binaries)


def test_unchanged_oversized_source_is_not_reported(monkeypatch):
    assert _fetch(monkeypatch, {"evil.py": _BIG, "a.py": b"x=1\n"},
                              {"evil.py": _BIG, "a.py": b"x=2\n"}) == []


def test_changed_oversized_source_is_still_reported(monkeypatch):
    assert _fetch(monkeypatch, {"evil.py": _BIG}, {"evil.py": _BIG + b"os.system('x')\n"}) == ["evil.py"]


def test_new_oversized_source_is_still_reported(monkeypatch):
    assert _fetch(monkeypatch, {"a.py": b"x=1\n"}, {"a.py": b"x=1\n", "evil.py": _BIG}) == ["evil.py"]


def test_unchanged_binary_and_foreign_file_are_not_reported(monkeypatch):
    members = {"ext.so": b"\x7fELF" + b"\0" * 64, "tool.php": b"<?php echo 1; ?>\n"}
    assert _fetch(monkeypatch, members, members) == []


def test_changed_binary_is_still_reported(monkeypatch):
    assert _fetch(monkeypatch, {"ext.so": b"\x00\x01"}, {"ext.so": b"\x00\x02"}) == ["ext.so"]


def test_everything_is_reported_when_the_prior_version_cannot_be_read(monkeypatch):
    assert _fetch(monkeypatch, {"evil.py": _BIG}, {"evil.py": _BIG}, prior_fails=True) == ["evil.py"]


def test_changed_foreign_file_is_still_reported(monkeypatch):
    assert _fetch(monkeypatch, {"tool.php": b"<?php echo 1; ?>\n"},
                               {"tool.php": b"<?php system($_GET['c']); ?>\n"}) == ["tool.php"]


def test_a_new_foreign_file_after_many_unchanged_ones_is_reported(monkeypatch):
    # Final review: the 25-file cap ran during extraction, before the comparison with the prior release,
    # so 25 unchanged foreign files used up the cap and a new .php after them was never recorded.
    old = {f"x{i:02}.php": b"<?php ?>" for i in range(25)}
    assert _fetch(monkeypatch, old, old | {"zz_new.php": b"<?php system($_GET['c']); ?>"}) == ["zz_new.php"]


def test_the_foreign_file_cap_applies_to_what_is_reported(monkeypatch):
    new = {f"x{i:02}.php": b"<?php ?>" for i in range(30)}
    assert len(_fetch(monkeypatch, {"a.py": b"x=1\n"}, new)) == Config().max_foreign_files
