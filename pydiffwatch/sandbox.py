"""Where package bytes are parsed (parse-sandbox spec §3). The parent keeps the network, the database, the reviewer
and the notifier; `compute` is everything that reads author bytes (unpack, diff, triage). `analyze` runs it
in-process ("off") or in a per-release worker (`_parse_worker.py`) under Seatbelt (macOS) or systemd-run (Linux):
no network, no writable file, no readable home directory, checkout, database, cache or lock directory, no program
but Python, no signal to another process, and none of this process's environment; its reply is read up to a cap.
The parent checks the worker's reply field by field and recomputes
the score. Either way, `analyze` then applies what only the parent may decide: the signal line from its own data,
and the dep and maintainer rule results from its own metadata (npm #31), merged in ruleset order.
The sandbox keeps a parser exploit away from the network, the database and the user's files. It cannot make an
exploited parser tell the truth about the package that exploited it."""
import dataclasses
import hashlib
import json
import logging
import math
import os
import shutil
import signal
import subprocess
import sys
import threading
from pathlib import Path

from . import differ, engine, execctx, fetcher
from .config import Config
from .models import Diff, Download, FileDiff, FiredRule, Hunk, TriageResult
from .rules import Rule

logger = logging.getLogger(__name__)

_backend = "off"      # set once per run by choose(): "seatbelt" | "systemd" | "off"
_PARENT_RULES = {"maintainer", "dep"}
_PATH_FIELDS = ("db_path", "cache_dir", "lock_path", "rules_dir")
_ROOT = Path(__file__).resolve().parent.parent      # the directory pydiffwatch is imported from
_PKG = _ROOT / "pydiffwatch"
_SYSTEMD_ENV = ("PATH", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS")
# What the probe must find. home_read may also be "unknown" (no readable file in HOME to try).
_PROBE_OK = {"network": "blocked", "write": "blocked", "db_read": "blocked", "env": "clean"}
_PROBE_OK_SEATBELT = {"exec": "blocked", "services": "blocked"}     # Linux children inherit the unit's limits
_PROBE_KEYS = {"network", "write", "home_read", "db_read", "exec", "services", "env"}
# Environment variables whose values are not secrets (the probe's env check hashes every other value >= 8 chars)
_PLAIN_ENV = {"PATH", "HOME", "USER", "LOGNAME", "SHELL", "LANG", "TERM", "TMPDIR", "PWD", "SHLVL", "_",
              "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "__CF_USER_TEXT_ENCODING"}


class SandboxError(Exception):
    """The parse sandbox is unavailable or failed; one release's scan failure, retried like a download failure."""


def compute(cfg, dl, ruleset):
    """Unpack, diff and triage one downloaded release. The single scan path for the in-process backend and the
    C2 worker: no owners (the parent's), no network."""
    art = fetcher.extract_download(cfg, dl)
    d = differ.build_diff(art)
    return art, d, engine.triage(d, cfg, ruleset)


def _with_parent_rules(cfg, dl, d, tr, owners, ruleset) -> TriageResult:
    """npm #31: the parent's own dep and maintainer results replace the scan's; every other rule's are the
    scan's. Merged in ruleset order, the order engine.triage fires in, so the stored fired list and the score
    equal a single triage with the owners (the score recomputed with max_total)."""
    parent = [r for r in ruleset if r.applies_to in _PARENT_RULES]
    meta = engine.triage(Diff(d.package, d.version, d.is_first_release, [], [], list(dl.added_dep_findings)),
                         cfg, parent, owners)
    fired = []
    for rule in ruleset:
        src = meta.fired_rules if rule.applies_to in _PARENT_RULES else tr.fired_rules
        fired += [f for f in src if f.rule == rule.id]
    total = engine.score(fired, ruleset)
    return TriageResult(total, fired, total >= cfg.threshold_t)


# ---- parent -> worker: one JSON line, then the raw sdists ----
def _home() -> str:
    return os.path.realpath(os.path.expanduser("~"))


def _import_paths() -> list[str]:
    """Where the worker imports from: the parent's own import path (so it runs exactly the parent's code), real
    paths only, and only the entries it needs: the directory pydiffwatch is imported from, the Python install, and
    a directory holding a module the worker imports (pydiffwatch, yaml). Every entry becomes readable to the worker,
    so anything else on sys.path (the daemon's cwd under `python -m`, a PYTHONPATH directory) stays closed. HOME and
    its ancestors never qualify: they would open up the whole home directory."""
    home = _home()
    prefixes = {os.path.realpath(sys.prefix), os.path.realpath(sys.base_prefix)}
    out = []
    for p in [str(_ROOT)] + sys.path:
        rp = os.path.realpath(p or os.getcwd())
        needed = (rp == str(_ROOT) or any(rp == x or rp.startswith(x.rstrip("/") + "/") for x in prefixes)
                  or any(os.path.exists(os.path.join(rp, m)) for m in ("pydiffwatch", "yaml", "yaml.py")))
        if needed and os.path.isdir(rp) and not (home == rp or home.startswith(rp.rstrip("/") + "/")) \
                and rp not in out:
            out.append(rp)
    return out


def _cfg_to_dict(cfg) -> dict:
    """Every Config field but the reviewer's and the webhook URL (credentials the worker never needs); the four paths resolved here, since the worker must never resolve a
    relative path against a directory of its own."""
    d = {f.name: getattr(cfg, f.name) for f in dataclasses.fields(cfg) if f.name not in ("reviewer", "webhook_url")}
    for k in _PATH_FIELDS:
        d[k] = str(Path(d[k]).resolve())
    return d


def _cfg_from_dict(d: dict) -> Config:
    return Config(**{k: (Path(v) if k in _PATH_FIELDS else v) for k, v in d.items()})


def _encode_input(cfg, dl: Download, ruleset) -> bytes:
    """The request: one JSON line (sort_keys), then new_blob, then prior_blob. The parent's loaded rules travel in
    it (npm #36: the worker never reads rules_dir). No owners, added_dep_findings or requires_dist_change: those
    facts are the parent's (spec decision 5)."""
    head = {"cfg": _cfg_to_dict(cfg), "sys_path": _import_paths(),
            "rules": [dataclasses.asdict(r) for r in ruleset],
            "dl": {"package": dl.package, "version": dl.version, "prior_version": dl.prior_version,
                   "is_new_package": dl.is_new_package, "maintainer_metadata": dl.maintainer_metadata,
                   "description": dl.description, "prior_error": dl.prior_error, "new_len": len(dl.new_blob),
                   "prior_len": None if dl.prior_blob is None else len(dl.prior_blob)}}
    return json.dumps(head, sort_keys=True).encode() + b"\n" + dl.new_blob + (dl.prior_blob or b"")


def _decode_input(head: dict, stream):
    """The worker's side of _encode_input: (Config, Download, ruleset). The Download carries no parent-owned
    facts: added_dep_findings=[] and requires_dist_change=None."""
    m = head["dl"]
    new = stream.read(m["new_len"])
    prior = stream.read(m["prior_len"]) if m["prior_len"] is not None else None
    if len(new) != m["new_len"] or (prior is not None and len(prior) != m["prior_len"]):
        raise ValueError("the request ended before its sdists did")
    dl = Download(m["package"], m["version"], m["prior_version"], m["is_new_package"], new, prior,
                  m["prior_error"], m["maintainer_metadata"], [], None, m["description"])
    return _cfg_from_dict(head["cfg"]), dl, [Rule(**r) for r in head["rules"]]


# ---- worker -> parent: JSON, checked field by field ----
def _encode_output(art, d: Diff, tr: TriageResult) -> bytes:
    """The reply: one JSON line (sort_keys). No signals, no added_dep_findings and no score: the parent's."""
    return json.dumps({
        "diff": {"package": d.package, "version": d.version, "is_first_release": d.is_first_release,
                 "changed": [{"path": f.path, "change_kind": f.change_kind, "new_text": f.new_text,
                              "hunks": [{"old_range": list(h.old_range), "new_range": list(h.new_range),
                                         "added": h.added, "removed": h.removed} for h in f.hunks]}
                             for f in d.changed],
                 "added_binaries": d.added_binaries, "description": d.description,
                 "exec_context": d.exec_context, "baseline_unavailable": d.baseline_unavailable,
                 "surface_omitted": d.surface_omitted, "requires_python": d.requires_python,
                 "file_classes": d.file_classes,
                 "hook_targets": [{"path": h.path, "change_kind": h.change_kind, "new_text": h.new_text,
                                   "run_by": h.run_by} for h in d.hook_targets]},
        "triage": {"fired_rules": [{"rule": r.rule, "weight": r.weight, "file": r.file, "lines": list(r.lines)}
                                   for r in tr.fired_rules]},
        "prior_error": art.prior_error}, sort_keys=True).encode()


def _check(ok: bool, what: str):
    if not ok:
        raise SandboxError(f"sandbox sent back a malformed {what}")


def _str(v, what, optional=False):
    _check(isinstance(v, str) or (optional and v is None), what)
    return v


def _list(v, what):
    _check(isinstance(v, list), what)
    return v


def _strs(v, what):
    _check(isinstance(v, list) and all(isinstance(x, str) for x in v), what)
    return v


def _pair(v, what):
    _check(isinstance(v, list) and len(v) == 2 and all(type(x) is int for x in v), what)
    return tuple(v)


def _dict(v, what):
    _check(isinstance(v, dict) and all(isinstance(k, str) for k in v), what)
    return v


def _decode_output(raw: bytes, cfg, dl: Download, ruleset):
    """Check the worker's reply field by field (spec §3.2 "Validation") and build the parent's own Diff and
    FiredRules from it. Returns (Diff, TriageResult, prior_error): the Diff has no signals and no
    added_dep_findings, and the score is recomputed here with max_total (analyze then re-merges the parent's dep
    and maintainer results). Keys the parent does not know are ignored. Raises fetcher.RefusedToExtract for a
    refusal inside the box, SandboxError for anything else."""
    try:
        out = json.loads(raw)
    except (ValueError, UnicodeDecodeError, RecursionError) as e:
        raise SandboxError(f"sandbox sent back something that is not JSON: {e}") from e
    _dict(out, "reply")
    if "error" in out:
        if out.get("error_type") == "RefusedToExtract":
            raise fetcher.RefusedToExtract(_str(out["error"], "refusal"))
        raise SandboxError(f"sandbox worker failed: {str(out['error'])[:500]}")
    try:
        dd = _dict(out["diff"], "diff")
        _check(dd["package"] == dl.package and dd["version"] == dl.version, "diff (wrong release)")
        _check(type(dd["is_first_release"]) is bool, "diff")
        changed = []
        for f in _list(dd["changed"], "file list"):
            _dict(f, "file diff")
            _check(f["change_kind"] in ("added", "removed", "modified"), "change kind")
            hunks = []
            for h in _list(f["hunks"], "hunk list"):
                _dict(h, "hunk")
                hunks.append(Hunk(_pair(h["old_range"], "hunk range"), _pair(h["new_range"], "hunk range"),
                                  _strs(h["added"], "hunk"), _strs(h["removed"], "hunk")))
            changed.append(FileDiff(_str(f["path"], "path"), f["change_kind"], hunks,
                                    _str(f["new_text"], "file text", optional=True)))
        bins = _list(dd["added_binaries"], "binary list")
        _check(all(isinstance(b, dict) and all(isinstance(k, str) and (v is None or type(v) in (str, int))
                                               for k, v in b.items()) for b in bins), "binary list")
        omitted = dd["surface_omitted"]
        _check(omitted is None or type(omitted) is int, "surface_omitted")
        requires_python = _str(dd["requires_python"], "requires_python", optional=True)
        _check(requires_python is None or len(requires_python) <= 4096, "requires_python")
        classes = _dict(dd["file_classes"], "file classes")
        _check(all(v in execctx.CLASSES for v in classes.values()), "file class")
        hooks = []
        for h in _list(dd["hook_targets"], "hook targets")[:differ._MAX_HOOK_TARGETS]:
            _dict(h, "hook target")
            _check(h["change_kind"] == "unchanged", "hook target kind")
            hooks.append(FileDiff(_str(h["path"], "path"), "unchanged", [], _str(h["new_text"], "file text"),
                                  run_by=_str(h["run_by"], "run by")))
        d = Diff(dd["package"], dd["version"], dd["is_first_release"], changed, bins, [],
                 _str(dd["description"], "description"), _str(dd["exec_context"], "exec context"),
                 _str(dd["baseline_unavailable"], "baseline"), omitted, "",
                 requires_python=requires_python, file_classes=classes, hook_targets=hooks)
        prior_error = _str(out["prior_error"], "prior_error", optional=True)
        known = {r.id for r in ruleset}
        fired = []
        for r in _list(_dict(out["triage"], "triage")["fired_rules"], "fired rules"):
            _dict(r, "fired rule")
            _check(r["rule"] in known, "rule id")
            w = r["weight"]
            _check(type(w) in (int, float) and math.isfinite(w) and w >= 0, "weight")
            fired.append(FiredRule(r["rule"], float(w), _str(r["file"], "rule file"),
                                   _pair(r["lines"], "rule lines")))
    except (KeyError, TypeError, AttributeError, OverflowError) as e:
        raise SandboxError(f"sandbox sent back a malformed reply: {e!r}") from e
    score = engine.score(fired, ruleset)
    return d, TriageResult(score, fired, score >= cfg.threshold_t), prior_error


# ---- launching the worker ----
def _readable() -> list[str]:
    """Directories the worker may read everything in: its import path, the Python install and the pydiffwatch
    package. A directory that contains pydiffwatch (the repo root, in a checkout) is left out, and the Seatbelt
    profile denies it (Ruling R13): only the package is opened up, not the repo's other files. rules_dir is not
    here: the rules travel in the request."""
    pkg = str(_PKG.resolve())
    paths = [p for p in _import_paths() if not (pkg + "/").startswith(p.rstrip("/") + "/")]
    paths += [pkg, os.path.realpath(sys.prefix), os.path.realpath(sys.base_prefix)]
    return list(dict.fromkeys(paths))


def _listable() -> list[str]:
    """Directories on the import path that contain pydiffwatch: listable so the import works, contents closed."""
    pkg = str(_PKG.resolve())
    return [p for p in _import_paths() if (pkg + "/").startswith(p.rstrip("/") + "/")]


def _private_dirs(cfg) -> list[str]:
    """The database, lock and cache directories, as real paths (Seatbelt matches real paths): never readable by
    the worker, wherever they are."""
    return list(dict.fromkeys([os.path.realpath(Path(cfg.db_path).parent),
                               os.path.realpath(Path(cfg.lock_path).parent), os.path.realpath(cfg.cache_dir)]))


def _cpu_seconds(cfg) -> int:
    return max(1, int(cfg.parse_timeout_s))


def _cpu_limit_code(cfg) -> str:
    """The worker's first statement (Ruling R2): its own CPU limit, set before pydiffwatch is imported or stdin
    read. A preexec_fn would run between fork and exec while the fetch pool's threads may hold locks."""
    cpu = _cpu_seconds(cfg)
    return f"import resource; resource.setrlimit(resource.RLIMIT_CPU, ({cpu}, {cpu + 1})); "


def _worker_argv(cfg) -> list[str]:
    # -I: ignore PYTHON* variables, the user site and the current directory; the parent's import path is sent in
    # the request instead, so the worker runs exactly the code the parent runs. Never a shell.
    return [sys.executable, "-I", "-c", _cpu_limit_code(cfg) +
            f"import sys; sys.path.insert(0, {str(_ROOT)!r}); from pydiffwatch._parse_worker import main; main()"]


def _quote(p: str) -> str:
    return '"' + p.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _seatbelt_profile(cfg) -> str:
    """Later rules win. Beyond network and writes it denies: starting any program but this Python, forking, Mach
    service lookups (LaunchServices could open a URL outside the sandbox), signalling any other process (a hijacked
    worker could SIGSTOP or SIGKILL this one), reading file data under HOME and under the directory pydiffwatch is
    imported from (metadata stays readable: realpath, stat and isdir keep working; the allow line below re-opens
    the package and the import path), and the private dirs wherever they are (Ruling R13)."""
    allow = " ".join(f"(subpath {_quote(p)})" for p in _readable())
    listable = " ".join(f"(literal {_quote(p)})" for p in _listable())
    private = " ".join(f"(subpath {_quote(p)})" for p in _private_dirs(cfg))
    exe = " ".join(f"(literal {_quote(p)})" for p in dict.fromkeys([sys.executable, os.path.realpath(sys.executable)]))
    return ("(version 1)\n(allow default)\n(deny network*)\n(deny file-write*)\n"
            "(deny process-exec*)\n"
            f"(allow process-exec {exe} (subpath {_quote(os.path.realpath(sys.base_prefix))}))\n"
            "(deny process-fork)\n(deny mach-lookup)\n(deny signal)\n"
            f"(deny file-read-data (subpath {_quote(_home())}) (subpath {_quote(str(_ROOT))}))\n"
            f"(allow file-read-data {allow}{' ' + listable if listable else ''})\n"
            f"(deny file-read-data {private})\n")


def _seatbelt_cmd(cfg) -> list[str]:
    return ["sandbox-exec", "-p", _seatbelt_profile(cfg)] + _worker_argv(cfg)


def _systemd_cmd(cfg) -> list[str]:
    """A transient unit (unexecuted on the maintainers' macOS machines, as in npm)."""
    user = os.geteuid() != 0
    cmd = ["systemd-run", "--pipe", "--wait", "--collect", "--quiet"] + (["--user"] if user else [])
    props = ["PrivateNetwork=yes", "ProtectSystem=strict", "ProtectHome=tmpfs", "PrivateTmp=yes",
             "NoNewPrivileges=yes", "SystemCallFilter=@system-service", f"MemoryMax={cfg.parse_memory_max}",
             f"RuntimeMaxSec={int(cfg.parse_timeout_s)}", "TasksMax=16"]
    if user:
        props.append("PrivateUsers=yes")        # a user manager needs its own user namespace for the rest
    props += [f"BindReadOnlyPaths=-{p}" for p in _readable()]
    props += [f"InaccessiblePaths=-{p}" for p in _private_dirs(cfg)]
    return cmd + [f"--property={p}" for p in props] + ["--"] + _worker_argv(cfg)


def _reply_cap(cfg) -> int:
    """The most a genuine reply can be: every changed source's new_text plus its hunk lines (each side bounded by
    max_total_bytes), JSON-escaped. A worker that sends more is writing garbage, and the parent must not buffer it."""
    return 4 * cfg.max_total_bytes


def _run(cfg, backend: str, payload: bytes) -> bytes:
    """Start one worker, send it `payload`, return its stdout. The worker gets none of this process's environment
    (API keys, tokens); systemd-run gets only what it needs to reach the service manager, and the unit it starts
    inherits none of that. Its stdout is read up to _reply_cap and its stderr only kept as a 500-byte tail, so a
    worker taken over by the package cannot make this process buffer without bound; the wall clock kills it
    (Ruling R12)."""
    if backend == "seatbelt":
        cmd, env = _seatbelt_cmd(cfg), {}
    elif backend == "systemd":
        cmd, env = _systemd_cmd(cfg), {k: os.environ[k] for k in _SYSTEMD_ENV if k in os.environ}
    else:
        raise SandboxError(f"unknown sandbox {backend!r}")
    wall, cap = cfg.parse_timeout_s + 10, _reply_cap(cfg)
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    except OSError as e:
        raise SandboxError(f"could not start the {backend} sandbox: {e}") from e
    timed_out, tail, out, over = threading.Event(), b"", bytearray(), False

    def feed():         # the worker reads its whole request before it answers; EPIPE means it died first
        try:
            proc.stdin.write(payload)
            proc.stdin.close()
        except OSError:
            pass

    def drain_stderr():     # Ruling R6: a traceback's error is its last line; the rest is never kept
        nonlocal tail
        for chunk in iter(lambda: proc.stderr.read1(65536), b""):
            tail = (tail + chunk)[-500:]

    timer = threading.Timer(wall, lambda: (timed_out.set(), proc.kill()))
    with proc:
        timer.start()
        threads = [threading.Thread(target=feed, daemon=True), threading.Thread(target=drain_stderr, daemon=True)]
        for t in threads:
            t.start()
        try:
            for chunk in iter(lambda: proc.stdout.read1(1 << 20), b""):
                out += chunk
                if len(out) > cap:
                    over = True
                    proc.kill()
                    break
            proc.wait()
        finally:        # an interrupted parent (Ctrl-C, SIGINT) kills its worker and leaves no armed Timer behind
            timer.cancel()
            if proc.poll() is None:
                proc.kill()
                proc.wait()
        for t in threads:
            t.join()
    if timed_out.is_set():
        raise SandboxError(f"{backend} sandbox timed out after {wall:.0f}s")
    if over:
        raise SandboxError(f"{backend} sandbox sent back more than {cap} bytes")
    if proc.returncode == -signal.SIGXCPU:
        raise SandboxError(f"{backend} sandbox timed out after {_cpu_seconds(cfg)}s of CPU")
    if proc.returncode != 0:
        raise SandboxError(f"{backend} sandbox exited {proc.returncode}: {tail.decode('utf-8', 'replace')}")
    return bytes(out)


def analyze(cfg, dl, owners, ruleset, backend=None):
    """Scan one downloaded release. Returns (Diff, TriageResult, prior_error). Raises fetcher.RefusedToExtract
    when the new sdist is refused; SandboxError when the sandbox fails or sends back anything malformed, or for a
    backend it does not know."""
    backend = backend or _backend
    if backend not in ("off", "seatbelt", "systemd"):
        raise SandboxError(f"unknown sandbox {backend!r}")
    if backend == "off" or dl.new_blob is None:     # Ruling R5: nothing downloaded, no author bytes to parse
        art, d, tr = compute(cfg, dl, ruleset)
        prior_error = art.prior_error
    else:
        d, tr, prior_error = _decode_output(_run(cfg, backend, _encode_input(cfg, dl, ruleset)), cfg, dl, ruleset)
    d = dataclasses.replace(d, added_dep_findings=list(dl.added_dep_findings),
                            signals=differ.render_signals(dl.requires_dist_change, dl.added_dep_findings,
                                                          d.added_binaries, owners))
    return d, _with_parent_rules(cfg, dl, d, tr, owners, ruleset), prior_error


# ---- proving the sandbox holds, before any package byte is parsed ----
def _home_sentinel() -> str | None:
    """A file in the home directory the worker must not be able to read."""
    home = _home()
    try:
        names = sorted(os.listdir(home))
    except OSError:
        return None
    for n in names:
        p = os.path.join(home, n)
        if os.path.isfile(p) and os.access(p, os.R_OK):
            return p
    return None


def probe(cfg, backend: str) -> dict:
    """Run the worker once in probe mode. It tries to reach the network, write next to the database, read the
    database directory and a file in HOME, start /usr/bin/true, look up a macOS service, and find this process's
    environment values (it gets their sha256 hashes, never the values). Returns {check: "blocked" | "open" |
    "unknown" | "n/a"}, with env "clean" | "leaked"."""
    db_dir = Path(cfg.db_path).resolve().parent
    db_dir.mkdir(parents=True, exist_ok=True)
    target = db_dir / f".sandbox-probe-write-{os.getpid()}"
    sentinel = db_dir / f".sandbox-probe-read-{os.getpid()}"
    sentinel.write_text("x")
    env_hashes = sorted({hashlib.sha256(v.encode("utf-8", "surrogateescape")).hexdigest()
                         for k, v in os.environ.items()
                         if k not in _PLAIN_ENV and not k.startswith("LC_") and len(v) >= 8})
    head = {"probe": True, "write_target": str(target), "db_file": str(sentinel), "home_file": _home_sentinel(),
            "env_hashes": env_hashes, "sys_path": _import_paths()}
    try:
        raw = _run(cfg, backend, json.dumps(head, sort_keys=True).encode() + b"\n")
    finally:
        for p in (target, sentinel):
            p.unlink(missing_ok=True)
    try:
        res = json.loads(raw)
    except (ValueError, UnicodeDecodeError, RecursionError) as e:
        raise SandboxError(f"sandbox probe sent back something that is not JSON: {e}") from e
    _check(isinstance(res, dict) and set(res) == _PROBE_KEYS, "probe result")
    return res


def _holds(res: dict, backend: str) -> bool:
    need = {**_PROBE_OK, **(_PROBE_OK_SEATBELT if backend == "seatbelt" else {})}
    return all(res.get(k) == v for k, v in need.items()) and res.get("home_read") != "open"


def choose(cfg, which=shutil.which, probe=probe, platform=sys.platform) -> str:
    """Pick this run's sandbox and prove it holds (spec decision 3). "auto" falls back to scanning in-process,
    loudly; "on" refuses (SandboxError); "off" never probes."""
    mode = cfg.parse_sandbox
    if mode == "off":
        return "off"
    backend = ("seatbelt" if platform == "darwin" and which("sandbox-exec")
               else "systemd" if platform.startswith("linux") and which("systemd-run") else None)
    why = "no sandbox-exec (macOS) or systemd-run (Linux) on this machine"
    if backend:
        try:
            res = probe(cfg, backend)
            if _holds(res, backend):
                return backend
            why = f"the {backend} sandbox did not hold: {res}"
        except SandboxError as e:
            why = f"the {backend} sandbox could not run: {e}"
    if mode == "on":
        raise SandboxError(f'parse_sandbox = "on" but {why}')
    msg = (f"[pydiffwatch] WARNING: scanning WITHOUT a sandbox ({why}). Package files are unpacked and parsed "
           f'inside this process. Set parse_sandbox = "on" to refuse to scan instead.')
    print(msg, flush=True)
    logger.warning(msg)
    return "off"
