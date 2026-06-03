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

_FORBIDDEN_BUILTINS = {"exec", "eval", "compile", "__import__"}
_FORBIDDEN_ATTRS = {"system", "popen", "Popen", "spawn"}  # os.system / os.popen / subprocess.Popen / pty.spawn


def _violations(src: str, forbidden_imports: set) -> list[str]:
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
                bad.append(f".{f.attr}()")
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
