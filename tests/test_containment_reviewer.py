"""Containment guard (§6 'artifacts are data, never code'). Two host-side modules handle the
reviewer path and must never execute, install, unpickle, or socket-fetch analyzed package content:

  * reviewer.py builds the prompt over the diff TEXT and parses JSON. It has ZERO network egress —
    it must not import any networking/exec/unpickle primitive at all.
  * backends.py is the single SANCTIONED egress: it may use stdlib urllib / the anthropic SDK to
    reach its CONFIGURED endpoint, but must never exec/install/unpickle or open raw sockets. That a
    URL embedded in package content can never become the egress target is proven behaviorally in
    test_backends.py (test_local_egress_url_is_config_endpoint_not_package_content).

These AST guards fail the suite if a future change introduces a forbidden primitive into either
module."""
import ast
import pathlib

_DIFFWATCH = pathlib.Path(__file__).resolve().parent.parent / "pydiffwatch"
_REVIEWER = _DIFFWATCH / "reviewer.py"
_BACKENDS = _DIFFWATCH / "backends.py"
_FETCHER = _DIFFWATCH / "fetcher.py"

# Importing these would enable executing/installing/unpickling package content, or fetching a URL
# found inside a package (§6.1 'never fetch a URL found inside a package').
_EXEC_INSTALL_UNPICKLE = {"subprocess", "pickle", "marshal", "importlib", "runpy",
                          "pip", "pkg_resources", "setuptools"}
_NETWORK = {"urllib", "http", "requests", "httpx", "socket", "ftplib"}

# reviewer.py: no egress whatsoever — forbid exec/install/unpickle AND every networking import.
_REVIEWER_FORBIDDEN = _EXEC_INSTALL_UNPICKLE | _NETWORK
# backends.py: the sanctioned egress. urllib (stdlib, audited) and the anthropic SDK are allowed; raw
# sockets and alternate HTTP stacks are not, and exec/install/unpickle is never allowed.
_BACKENDS_FORBIDDEN = _EXEC_INSTALL_UNPICKLE | {"socket", "ftplib", "requests", "httpx"}

# fetcher.py: the hot path for untrusted package bytes (download + in-memory extraction). urllib is
# the sanctioned ingest egress (PyPI), so it's allowed; everything that could execute/install/unpickle
# package content, open raw sockets, or stage package bytes ON DISK is forbidden. The artifacts-are-
# data invariant requires extraction to stay in memory — no extractall/extract, no write-mode open,
# no tempfile/shutil.
_FETCHER_FORBIDDEN = _EXEC_INSTALL_UNPICKLE | {"socket", "ftplib", "requests", "httpx",
                                               "tempfile", "shutil"}

# guard.py: decides whether/how much to send; it reaches the model only through the backend, so it gets
# no egress of its own. hostmem.py: host memory via ctypes (macOS) and /proc (Linux) only — no subprocess
# (no `vm_stat`/`sysctl` shell-outs) and no network; urllib.parse (hostname of the endpoint) is allowed,
# checked separately by _urllib_beyond_parse.
_GUARD_FORBIDDEN = _EXEC_INSTALL_UNPICKLE | _NETWORK
_HOSTMEM_FORBIDDEN = _EXEC_INSTALL_UNPICKLE | (_NETWORK - {"urllib"})

_FORBIDDEN_BUILTINS = {"exec", "eval", "compile", "__import__"}
_FORBIDDEN_ATTRS = {"system", "popen", "Popen", "spawn"}  # os.system / os.popen / subprocess.Popen / pty.spawn


def _violations(src: str, forbidden_imports: set, allowed_calls=frozenset()) -> list[str]:
    """allowed_calls: exact `module.attr` calls exempt from _FORBIDDEN_ATTRS (e.g. platform.system)."""
    tree = ast.parse(src)
    bad: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            bad += [f"import {a.name}" for a in node.names if a.name.split(".")[0] in forbidden_imports]
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] in forbidden_imports:
                bad.append(f"from {node.module} import ...")
        elif isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name) and f.id in _FORBIDDEN_BUILTINS:
                bad.append(f"{f.id}()")
            elif isinstance(f, ast.Attribute) and f.attr in _FORBIDDEN_ATTRS:
                if isinstance(f.value, ast.Name) and f"{f.value.id}.{f.attr}" in allowed_calls:
                    continue
                bad.append(f".{f.attr}()")
    return bad


def _urllib_beyond_parse(src: str) -> list[str]:
    """Any urllib import other than urllib.parse (which parses strings and cannot fetch)."""
    bad: list[str] = []
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Import):
            bad += [f"import {a.name}" for a in node.names
                    if a.name.split(".")[0] == "urllib" and a.name != "urllib.parse"]
        elif isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "urllib":
            if node.module != "urllib.parse":
                bad.append(f"from {node.module} import ...")
    return bad


def _disk_violations(src: str) -> list[str]:
    """Flag anything that would write package bytes to disk or extract a tar to disk: tar.extractall /
    .extract, or a write/append/exclusive-mode open()."""
    tree = ast.parse(src)
    bad: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if isinstance(f, ast.Attribute) and f.attr in {"extractall", "extract"}:
            bad.append(f".{f.attr}()")
        if isinstance(f, ast.Name) and f.id == "open":
            mode = None
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                mode = node.args[1].value
            for kw in node.keywords:
                if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                    mode = kw.value.value
            if isinstance(mode, str) and any(c in mode for c in ("w", "a", "x", "+")):
                bad.append(f"open(mode={mode!r})")
    return bad


def test_reviewer_has_no_egress_or_exec():
    bad = _violations(_REVIEWER.read_text(), _REVIEWER_FORBIDDEN)
    assert not bad, ("reviewer.py must have zero network egress and never exec/install/unpickle "
                     f"(§6 data-never-code); found: {bad}")


def test_backends_only_sanctioned_egress_never_exec_install_unpickle():
    bad = _violations(_BACKENDS.read_text(), _BACKENDS_FORBIDDEN)
    assert not bad, ("backends.py may use urllib/anthropic to its configured endpoint, but must never "
                     f"exec/install/unpickle or open raw sockets (§6); found: {bad}")


def test_fetcher_stays_in_memory_never_exec_install_unpickle():
    src = _FETCHER.read_text()
    bad = _violations(src, _FETCHER_FORBIDDEN)
    assert not bad, ("fetcher.py downloads + extracts untrusted package bytes; it may use urllib "
                     f"(sanctioned PyPI ingest) but must never exec/install/unpickle/socket (§6); found: {bad}")
    disk = _disk_violations(src)
    assert not disk, ("fetcher.py must extract IN MEMORY only — no extractall/extract, no write-mode "
                      f"open (artifacts are data, never code); found: {disk}")


def test_guard_actually_detects_a_violation():
    # meta-test: the guard must FAIL on known-bad snippets, so it can't vacuously pass on everything.
    assert _violations("import subprocess\n", _REVIEWER_FORBIDDEN)
    assert _violations("exec('payload')\n", _REVIEWER_FORBIDDEN)
    assert _violations("import os\nos.system('x')\n", _REVIEWER_FORBIDDEN)
    assert _violations("import urllib.request\n", _REVIEWER_FORBIDDEN)        # egress banned in reviewer
    assert _violations("import subprocess\n", _BACKENDS_FORBIDDEN)            # exec banned in backends too
    assert _violations("import socket\n", _BACKENDS_FORBIDDEN)               # raw sockets banned in backends
    # backends legitimately uses urllib + anthropic; those must NOT be flagged for backends.
    assert not _violations("import urllib.request\nimport anthropic\n", _BACKENDS_FORBIDDEN)
    assert not _violations("import json\njson.loads('{}')\n", _REVIEWER_FORBIDDEN)  # json parsing is safe
    # fetcher guard: install/socket/disk-staging banned, but its sanctioned urllib ingest is allowed.
    assert _violations("import subprocess\n", _FETCHER_FORBIDDEN)
    assert _violations("import shutil\n", _FETCHER_FORBIDDEN)
    assert not _violations("import urllib.request\n", _FETCHER_FORBIDDEN)     # sanctioned PyPI ingest egress
    assert _disk_violations("tar.extractall('/tmp')\n")                       # never extract to disk
    assert _disk_violations("open('x', 'w')\n") and _disk_violations("open('x', mode='wb')\n")
    assert not _disk_violations("open('x')\n") and not _disk_violations("open('x', 'r')\n")


def test_guard_and_hostmem_never_exec_or_open_their_own_egress():
    # guard.py reaches the model only through the backend; hostmem.py reads memory via ctypes and /proc only
    # (its one urllib import is urllib.parse, to read the endpoint's hostname — no fetch).
    bad = _violations((_DIFFWATCH / "guard.py").read_text(), _GUARD_FORBIDDEN)
    assert not bad, f"guard.py must never exec/install/unpickle or open its own egress (§6); found: {bad}"
    src = (_DIFFWATCH / "hostmem.py").read_text()
    bad = (_violations(src, _HOSTMEM_FORBIDDEN, allowed_calls={"platform.system"})   # the OS name, not os.system
           + _urllib_beyond_parse(src) + _disk_violations(src))
    assert not bad, f"hostmem.py must stay ctypes and /proc only, no subprocess or egress (§6); found: {bad}"


def test_guard_and_hostmem_bans_detect_violations():
    assert _violations("import subprocess\n", _GUARD_FORBIDDEN)
    assert _violations("import urllib.request\n", _GUARD_FORBIDDEN)
    assert _violations("import subprocess\n", _HOSTMEM_FORBIDDEN)
    assert _violations("import socket\n", _HOSTMEM_FORBIDDEN)
    assert _violations("import os\nos.popen('vm_stat')\n", _HOSTMEM_FORBIDDEN)
    assert _violations("import os\nos.system('x')\n", _HOSTMEM_FORBIDDEN, allowed_calls={"platform.system"})
    assert not _violations("import platform\nplatform.system()\n", _HOSTMEM_FORBIDDEN, allowed_calls={"platform.system"})
    assert _urllib_beyond_parse("import urllib.request\n") and _urllib_beyond_parse("from urllib import request\n")
    assert not _urllib_beyond_parse("from urllib.parse import urlsplit\nimport ctypes\n")


# facts.py parses untrusted package source with ast.parse and walks it: no exec, no import machinery (site,
# importlib), no network, no disk writes.
_FACTS_FORBIDDEN = _EXEC_INSTALL_UNPICKLE | _NETWORK | {"site"}


def test_facts_only_parses_never_executes_imports_or_fetches():
    src = (_DIFFWATCH / "facts.py").read_text()
    bad = _violations(src, _FACTS_FORBIDDEN) + _disk_violations(src)
    assert not bad, f"facts.py must only ast.parse package source, never run or fetch it (§6); found: {bad}"


def test_facts_ban_detects_violations():
    assert _violations("import site\n", _FACTS_FORBIDDEN)
    assert _violations("from importlib import import_module\n", _FACTS_FORBIDDEN)
    assert _violations("import urllib.request\n", _FACTS_FORBIDDEN)
    assert _violations("compile(src, 'x', 'exec')\n", _FACTS_FORBIDDEN)
    assert not _violations("import ast\nast.parse(src)\n", _FACTS_FORBIDDEN)


# execctx.py reads author-written build metadata (pyproject.toml, setup.cfg, setup.py, entry_points.txt, .pth)
# with tomllib / configparser / ast / email.parser only: pure, no exec, no import machinery, no network, no disk.
_EXECCTX_FORBIDDEN = _FACTS_FORBIDDEN


def test_execctx_only_parses_never_executes_imports_or_fetches():
    src = (_DIFFWATCH / "execctx.py").read_text()
    bad = _violations(src, _EXECCTX_FORBIDDEN) + _disk_violations(src)
    assert not bad, f"execctx.py must only statically parse build metadata, never run it (§6); found: {bad}"
    assert "open(" not in src, "execctx.py is pure: it gets bytes, it never opens files"


# ---- the parse sandbox: the only process launches in pydiffwatch ----

def _attr_chain(node) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _process_calls(tree) -> list:
    """(innermost enclosing function name, call) for every subprocess.* call; "<module>" at module level.
    ast.walk visits outer functions first, so the last function written for a call is its innermost."""
    innermost = {}
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for c in ast.walk(fn):
                if isinstance(c, ast.Call) and _attr_chain(c.func).startswith("subprocess."):
                    innermost[id(c)] = (fn.name, c)
    for c in ast.walk(tree):
        if isinstance(c, ast.Call) and _attr_chain(c.func).startswith("subprocess.") and id(c) not in innermost:
            innermost[id(c)] = ("<module>", c)
    return list(innermost.values())


def _launch_pin(src: str, *, only_in=None, argv=None, call="subprocess.run") -> list[str]:
    """What breaks a module's launch pin: anything but exactly one `call`; a shell= keyword; subprocess
    imported under another name or from-imported (which would hide a call from the count); with only_in, the call
    outside that function; with argv, a first argument other than that literal list."""
    tree = ast.parse(src)
    bad = [f"import subprocess as {a.asname}" for n in ast.walk(tree) if isinstance(n, ast.Import)
           for a in n.names if a.name == "subprocess" and a.asname]
    bad += [f"from {n.module} import ..." for n in ast.walk(tree)
            if isinstance(n, ast.ImportFrom) and (n.module or "").split(".")[0] == "subprocess"]
    calls = _process_calls(tree)
    if [_attr_chain(c.func) for _, c in calls] != [call]:
        bad.append(f"process launches: {[_attr_chain(c.func) for _, c in calls]}")
    for fn, c in calls:
        if any(kw.arg == "shell" for kw in c.keywords):
            bad.append("shell=")
        if only_in is not None and fn != only_in:
            bad.append(f"a launch in {fn}")
        if argv is not None and not (c.args and isinstance(c.args[0], ast.List)
                                     and [getattr(e, "value", None) for e in c.args[0].elts] == argv):
            bad.append("another program")
    return bad


def _imports(src: str) -> set[str]:
    out = set()
    for n in ast.walk(ast.parse(src)):
        if isinstance(n, ast.Import):
            out |= {a.name.split(".")[0] for a in n.names}
        elif isinstance(n, ast.ImportFrom) and n.module and n.level == 0:
            out.add(n.module.split(".")[0])
    return out


_SANDBOX_FORBIDDEN = (_EXEC_INSTALL_UNPICKLE - {"subprocess"}) | _NETWORK


def test_sandbox_only_launches_its_worker_without_a_shell():
    src = (_DIFFWATCH / "sandbox.py").read_text()
    assert _launch_pin(src, call="subprocess.Popen") == []      # Ruling R12: one Popen, its stdout read up to a cap
    launchers = {n.value for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Constant)
                 and n.value in {"sandbox-exec", "systemd-run"}}
    assert launchers == {"sandbox-exec", "systemd-run"}
    bad = _violations(src, _SANDBOX_FORBIDDEN, allowed_calls={"subprocess.Popen"})
    assert not bad, f"sandbox.py launches the worker and nothing else; no network, no exec (§6); found: {bad}"


_GOOD_SANDBOX = ("import subprocess\n"
                 "def _run(cmd, env):\n"
                 "    return subprocess.run(cmd, input=b'', capture_output=True, timeout=1, env=env)\n")


def test_the_launch_pin_catches_a_second_launch_a_shell_and_an_alias():
    assert _launch_pin(_GOOD_SANDBOX) == []
    assert _launch_pin(_GOOD_SANDBOX + "def other():\n    subprocess.run(['sh'])\n")
    assert _launch_pin(_GOOD_SANDBOX.replace("env=env)", "env=env, shell=True)"))
    assert _launch_pin(_GOOD_SANDBOX.replace("subprocess.run(", "subprocess.Popen("))
    assert _launch_pin(_GOOD_SANDBOX, call="subprocess.Popen")
    assert _launch_pin("import subprocess as sp\n" + _GOOD_SANDBOX)
    assert _launch_pin("from subprocess import run\n" + _GOOD_SANDBOX)


def test_only_the_sandbox_and_its_worker_can_start_a_process():
    offenders = [p.name for p in sorted(_DIFFWATCH.glob("*.py"))
                 if p.name not in ("sandbox.py", "_parse_worker.py") and {"subprocess", "pty"} & _imports(p.read_text())]
    assert offenders == [], f"only sandbox.py and _parse_worker.py may start a process; found: {offenders}"
