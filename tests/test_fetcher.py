import dataclasses
from pydiffwatch import fetcher
from pydiffwatch.config import Config
from pydiffwatch.models import NewRelease
from tests.fixtures.build_fixtures import make_sdist, make_raw_member
import pytest


def _meta(pkg, versions):
    """Build a synthetic PyPI package-JSON. versions: list of (ver, iso_ts[, has_sdist[, yanked]])."""
    releases = {}
    for spec in versions:
        ver, ts = spec[0], spec[1]
        has_sdist = spec[2] if len(spec) > 2 else True
        yanked = spec[3] if len(spec) > 3 else False
        releases[ver] = ([{"packagetype": "sdist", "url": f"mock://{pkg}/{ver}",
                           "upload_time_iso_8601": ts, "yanked": yanked}] if has_sdist else
                         [{"packagetype": "bdist_wheel", "url": f"mock://{pkg}/{ver}.whl",
                           "upload_time_iso_8601": ts}])
    return {"releases": releases}

def test_extracts_source_only():
    blob = make_sdist({"setup.py": b"import os\n", "mod/__init__.py": b"x=1\n",
                       "ext.so": b"\x00\x01\x02"})
    files, binaries = fetcher.extract_sdist(blob, Config())
    assert "setup.py" in files and "mod/__init__.py" in files
    assert "ext.so" not in files
    assert any(b["path"] == "ext.so" and "sha256" in b for b in binaries)

def test_tar_slip_rejected():
    blob = make_raw_member("../evil.py", b"x=1\n")
    files, _ = fetcher.extract_sdist(blob, Config())
    assert files == {}   # path-escape member ignored, nothing written anywhere

def test_member_size_cap():
    big = b"a" * (2 * 1024 * 1024)
    blob = make_sdist({"big.py": big})
    with pytest.raises(fetcher.RefusedToExtract):
        fetcher.extract_sdist(blob, Config(max_member_bytes=1024 * 1024))

def test_oversized_source_recorded_not_dropped():
    big_py = b"# pad\n" + b"x = 1  # filler\n" * 200000   # > 1 MB
    blob = make_sdist({"evil.py": big_py, "ok.py": b"y=2\n"})
    files, binaries = fetcher.extract_sdist(blob, Config())
    assert "ok.py" in files
    assert "evil.py" not in files                      # too big to analyze...
    rec = next(b for b in binaries if b["path"] == "evil.py")
    assert rec["reason"] == "source-too-large"         # ...but recorded as a signal

def test_malformed_archive_raises_refused():
    import pytest
    with pytest.raises(fetcher.RefusedToExtract):
        fetcher.extract_sdist(b"this is not a gzip tarball", Config())

def _pax_name_bomb(name_bytes: int) -> bytes:
    # A 0-byte file whose NAME is huge: gzips tiny (repetitive), but tarfile must materialise the
    # full PAX 'path' record to parse the header. Defeats every m.size-based cap.
    import io, tarfile
    name = "d/" + "a" * name_bytes
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.PAX_FORMAT) as t:
        ti = tarfile.TarInfo(name); ti.size = 0
        t.addfile(ti, io.BytesIO(b""))
    return buf.getvalue()

def test_name_bomb_refused_by_decompressed_ceiling():
    # A multi-MB name exceeding the decompressed ceiling must be refused, not materialised in RAM.
    blob = _pax_name_bomb(8 * 1024 * 1024)        # 8 MB name -> trips a 4 MB ceiling mid-read
    assert len(blob) < 1024 * 1024                # ...yet the gzipped blob is tiny
    with pytest.raises(fetcher.RefusedToExtract):
        fetcher.extract_sdist(blob, Config(max_decompressed_bytes=4 * 1024 * 1024))

def test_long_member_name_refused_by_name_cap():
    # A name over max_name_bytes but under the decompressed ceiling is caught by the name guard.
    blob = _pax_name_bomb(5000)                   # 5000-byte name > max_name_bytes(4096)
    with pytest.raises(fetcher.RefusedToExtract):
        fetcher.extract_sdist(blob, Config())     # default 120 MB ceiling does not fire; name cap does

def test_decompressed_ceiling_bounds_total_stream():
    # Total decompressed bytes over the ceiling are refused even when every per-member cap is met.
    members = {f"f{i}.txt": b"x" * (900 * 1024) for i in range(8)}   # 8 x ~0.9MB = ~7MB decompressed
    blob = make_sdist(members)
    with pytest.raises(fetcher.RefusedToExtract):
        fetcher.extract_sdist(blob, Config(max_decompressed_bytes=2 * 1024 * 1024))


# ---- foreign-language-code anomaly: non-Python source in a pip sdist ----

def test_foreign_source_recorded():
    blob = make_sdist({"setup.py": b"from setuptools import setup\n",
                       "app/login.php": b"<?php echo 'hi'; ?>", "pkg/__init__.py": b"x=1\n"})
    files, binaries = fetcher.extract_sdist(blob, Config())
    assert "setup.py" in files and "pkg/__init__.py" in files     # python still extracted
    assert "app/login.php" not in files                            # foreign bytes never read
    rec = next(b for b in binaries if b["path"] == "app/login.php")
    assert rec["reason"] == "foreign-language-source" and rec["ext"] == ".php"
    assert "sha256" not in rec                                     # presence is the signal; no content read

def test_legitimate_cext_and_assets_not_foreign():
    blob = make_sdist({"setup.py": b"x=1\n", "_speedups.c": b"int main(){}\n",
                       "src/parser.pyx": b"def f(): pass\n", "vendor/jquery.js": b"//js\n",
                       "scripts/build.sh": b"#!/bin/sh\n", "conf/app.yaml": b"a: 1\n"})
    _, binaries = fetcher.extract_sdist(blob, Config())
    assert not any(b.get("reason") == "foreign-language-source" for b in binaries)

def test_foreign_case_insensitive_and_double_extension():
    blob = make_sdist({"setup.py": b"x=1\n", "A.PHP": b"<?php ?>", "setup.py.php": b"<?php ?>"})
    _, binaries = fetcher.extract_sdist(blob, Config())
    foreign = {b["path"] for b in binaries if b.get("reason") == "foreign-language-source"}
    assert foreign == {"A.PHP", "setup.py.php"}

def test_foreign_per_package_cap():
    members = {"setup.py": b"x=1\n"} | {f"x{i}.php": b"<?php ?>" for i in range(30)}
    blob = make_sdist(members)
    _, binaries = fetcher.extract_sdist(blob, Config(max_foreign_files=25))
    assert sum(1 for b in binaries if b.get("reason") == "foreign-language-source") == 25


# ---- fetch_artifacts: PyPI-baseline resolution + new-package policy ----

def test_update_diffs_against_pypi_predecessor(monkeypatch):
    monkeypatch.setattr(fetcher, "_package_json", lambda p, cfg: _meta("acme", [
        ("1.0", "2026-01-01T00:00:00Z"), ("1.1", "2026-02-01T00:00:00Z")]))
    blobs = {"mock://acme/1.0": make_sdist({"acme/__init__.py": b"x = 1\n"}),
             "mock://acme/1.1": make_sdist({"acme/__init__.py": b"x = 2\n"})}
    monkeypatch.setattr(fetcher, "_download", lambda url, cfg: blobs[url])
    art = fetcher.fetch_artifacts(Config(), NewRelease("acme", "1.1", 5))
    assert art.is_new_package is False
    assert art.prior_version == "1.0"                      # baseline came from PyPI, not our DB
    assert art.prior_files["acme/__init__.py"] == b"x = 1\n"
    assert art.new_files["acme/__init__.py"] == b"x = 2\n"


def test_new_package_scans_surface_only(monkeypatch):
    monkeypatch.setattr(fetcher, "_package_json", lambda p, cfg: _meta("brandnew", [
        ("1.0", "2026-01-01T00:00:00Z")]))                # single version => genuinely new package
    monkeypatch.setattr(fetcher, "_download", lambda url, cfg: make_sdist({
        "setup.py": b"import os\nos.system('x')\n",
        "brandnew/__init__.py": b"import requests\n",
        "brandnew/big_model.py": b"# bulk library code\n" * 5000}))
    art = fetcher.fetch_artifacts(Config(), NewRelease("brandnew", "1.0", 5))   # default policy=surface
    assert art.is_new_package is True and art.prior_version is None
    assert set(art.new_files) == {"setup.py", "brandnew/__init__.py"}   # bulk module dropped, no truncation


def test_new_package_skip_policy_downloads_nothing(monkeypatch):
    monkeypatch.setattr(fetcher, "_package_json", lambda p, cfg: _meta("np", [("1.0", "2026-01-01T00:00:00Z")]))
    calls = {"n": 0}
    monkeypatch.setattr(fetcher, "_download", lambda url, cfg: calls.__setitem__("n", calls["n"] + 1) or b"")
    art = fetcher.fetch_artifacts(dataclasses.replace(Config(), new_package_policy="skip"),
                                  NewRelease("np", "1.0", 5))
    assert art.is_new_package is True and art.new_files == {}
    assert calls["n"] == 0                                 # skip policy never downloads the sdist


def test_predecessor_ignores_yanked_and_wheel_only(monkeypatch):
    monkeypatch.setattr(fetcher, "_package_json", lambda p, cfg: _meta("acme", [
        ("1.0", "2026-01-01T00:00:00Z"),                   # valid predecessor
        ("1.1", "2026-02-01T00:00:00Z", True, True),       # yanked sdist -> not a baseline
        ("1.2", "2026-03-01T00:00:00Z", False),            # wheel-only (no sdist) -> not a baseline
        ("1.3", "2026-04-01T00:00:00Z")]))                 # target
    blobs = {"mock://acme/1.0": make_sdist({"a/__init__.py": b"x = 1\n"}),
             "mock://acme/1.3": make_sdist({"a/__init__.py": b"x = 9\n"})}
    monkeypatch.setattr(fetcher, "_download", lambda url, cfg: blobs[url])
    art = fetcher.fetch_artifacts(Config(), NewRelease("acme", "1.3", 5))
    assert art.prior_version == "1.0"                      # skipped yanked 1.1 and wheel-only 1.2


def test_no_sdist_returns_none(monkeypatch):
    monkeypatch.setattr(fetcher, "_package_json", lambda p, cfg: _meta("wheelpkg", [
        ("1.0", "2026-01-01T00:00:00Z", False)]))          # wheel-only release
    assert fetcher.fetch_artifacts(Config(), NewRelease("wheelpkg", "1.0", 5)) is None


def test_fetch_captures_maintainer_metadata(monkeypatch):
    meta = _meta("acme", [("1.0", "2026-01-01T00:00:00Z"), ("1.1", "2026-02-01T00:00:00Z")])
    meta["info"] = {"author": "Alice", "author_email": "alice@x.io",
                    "maintainer": "Bob", "maintainer_email": "bob@x.io"}
    meta["ownership"] = {"roles": [{"role": "Owner", "user": "alice"},
                                   {"role": "Maintainer", "user": "bob"}]}
    monkeypatch.setattr(fetcher, "_package_json", lambda p, cfg: meta)
    blobs = {"mock://acme/1.0": make_sdist({"acme/__init__.py": b"x=1\n"}),
             "mock://acme/1.1": make_sdist({"acme/__init__.py": b"x=2\n"})}
    monkeypatch.setattr(fetcher, "_download", lambda url, cfg: blobs[url])
    art = fetcher.fetch_artifacts(Config(), NewRelease("acme", "1.1", 9))
    assert art.maintainer_metadata == {"author": "Alice", "maintainer": "Bob",
                                       "roles": ["alice", "bob"], "upload_time": "2026-02-01T00:00:00Z"}
    assert "author_email" not in art.maintainer_metadata        # PII deliberately omitted
    assert "maintainer_email" not in art.maintainer_metadata


# ---- signal 5: added-dependency reputation screening (requires_dist diff) ----

def test_fetch_screens_added_dependencies(monkeypatch):
    from datetime import datetime, timezone, timedelta
    meta = _meta("acme", [("1.0", "2026-01-01T00:00:00Z"), ("1.1", "2026-02-01T00:00:00Z")])
    meta["info"] = {"requires_dist": ["requests", "reqursts", "freshpkg"]}   # new version's declared deps
    monkeypatch.setattr(fetcher, "_package_json", lambda p, cfg: meta)
    monkeypatch.setattr(fetcher, "_requires_dist", lambda pkg, ver, cfg: ["requests"])  # 1.0 had only requests
    fresh_ts = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    monkeypatch.setattr(fetcher, "_dep_json",
                        lambda name, cfg: {"releases": {"1.0": [{"upload_time_iso_8601": fresh_ts}]}})
    blobs = {"mock://acme/1.0": make_sdist({"acme/__init__.py": b"x=1\n"}),
             "mock://acme/1.1": make_sdist({"acme/__init__.py": b"x=2\n"})}
    monkeypatch.setattr(fetcher, "_download", lambda url, cfg: blobs[url])
    art = fetcher.fetch_artifacts(Config(), NewRelease("acme", "1.1", 9))
    reasons = {f["name"]: f["reason"] for f in art.added_dep_findings}
    assert reasons.get("reqursts") == "typosquat"      # added + close to 'requests', decided locally
    assert reasons.get("freshpkg") == "brand-new"      # added + first published 2 days ago
    assert "requests" not in reasons                   # popular -> whitelisted, not flagged


def test_fetch_no_dep_findings_when_new_version_declares_none(monkeypatch):
    # The common case: no info.requires_dist -> empty added set -> no screening, no extra network.
    monkeypatch.setattr(fetcher, "_package_json", lambda p, cfg: _meta("acme", [
        ("1.0", "2026-01-01T00:00:00Z"), ("1.1", "2026-02-01T00:00:00Z")]))
    blobs = {"mock://acme/1.0": make_sdist({"acme/__init__.py": b"x=1\n"}),
             "mock://acme/1.1": make_sdist({"acme/__init__.py": b"x=2\n"})}
    monkeypatch.setattr(fetcher, "_download", lambda url, cfg: blobs[url])
    art = fetcher.fetch_artifacts(Config(), NewRelease("acme", "1.1", 9))
    assert art.added_dep_findings == []
