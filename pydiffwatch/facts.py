"""Fact extraction for the rules engine. Computes a RuleContext from a Diff: per-file import-bound
primitive categories, encoded-blob signal, syntax-error, location weight; plus normalized binary/dep
findings and the maintainer-change flag. Pure and deterministic. Static AST analysis only — no execution.

The import-binding machinery (_build_import_table / _resolve_call / _PRIM_BINDINGS) is the PUBLIC half of
main DiffWatch's triage: a call counts as a dangerous primitive only when its receiver resolves via the
file's import table to an origin in the name's allowlist (so re.compile != exec, json.loads != decode).
The private decode->exec dataflow taint chain is NOT part of this engine (held back upstream)."""
import ast
import math
import posixpath
import re
from dataclasses import dataclass

BUILTIN_EXEC = {"exec", "eval", "compile", "__import__"}   # dangerous as bare builtins (no receiver)
_NET_ORIGINS = {"requests", "httpx", "urllib3", "aiohttp", "http.client"}
# name -> (category, set of qualifying origin modules). Bare builtins in BUILTIN_EXEC handled separately.
_PRIM_BINDINGS = {
    "system": ("process", {"os"}), "popen": ("process", {"os"}),
    "Popen": ("process", {"subprocess"}), "run": ("process", {"subprocess"}),
    "call": ("process", {"subprocess"}), "check_output": ("process", {"subprocess"}),
    "check_call": ("process", {"subprocess"}),
    "urlopen": ("network", {"urllib", "urllib.request"}),
    "Request": ("network", {"urllib", "urllib.request"}),
    "urlretrieve": ("network", {"urllib", "urllib.request"}),
    "get": ("network", _NET_ORIGINS), "post": ("network", _NET_ORIGINS),
    "request": ("network", _NET_ORIGINS), "socket": ("network", {"socket"}),
    "b64decode": ("decode", {"base64"}), "urlsafe_b64decode": ("decode", {"base64"}),
    "b16decode": ("decode", {"base64"}), "b32decode": ("decode", {"base64"}),
    "a85decode": ("decode", {"base64"}), "unhexlify": ("decode", {"binascii"}),
    "decompress": ("decode", {"zlib", "gzip", "bz2", "lzma"}),
    "loads": ("decode", {"pickle", "marshal", "dill"}),     # NOT json/yaml/toml — safe deserializers
    "load": ("decode", {"pickle", "marshal", "dill"}),
    "getenv": ("credential", {"os"}), "expanduser": ("credential", {"os.path", "posixpath"}),
}
ENTROPY_X, ENTROPY_WINDOW, LONG_RUN_L, LONG_LINE = 4.5, 64, 128, 500
_B64_RUN = re.compile(r"[A-Za-z0-9+/=]{%d,}" % LONG_RUN_L)


def classify_location(path: str) -> float:
    base = posixpath.basename(path)
    if base in {"setup.py", "setup.cfg", "pyproject.toml"} or \
       base in {"__init__.py", "conftest.py", "sitecustomize.py"} or path.endswith(".pth"):
        return 3.0
    segs = path.split("/")
    if any(s in {"tests", "test", "docs", "doc", "examples", "example"} for s in segs):
        return 0.2
    return 1.0


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _build_import_table(tree) -> dict:
    """Map each bound name to its origin module string. `import os` -> {os: os};
    `import os.path as p` -> {p: os.path}; `from os import system` -> {system: os}."""
    table: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                table[a.asname or a.name.split(".")[0]] = a.name
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""                       # relative (level>0) -> "" -> matches nothing
            for a in node.names:
                table[a.asname or a.name] = mod
    return table


def _resolved_module(func):
    """For an attribute-call func (a.b.c(...)), return (root_name, [middle attrs], called_name).
    None when the receiver is not a plain dotted name (e.g. session.get where session is a call result)."""
    attrs: list[str] = []
    node = func
    while isinstance(node, ast.Attribute):
        attrs.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    attrs.reverse()
    return node.id, attrs[:-1], attrs[-1]


def _category_for(name: str, module: str):
    b = _PRIM_BINDINGS.get(name)
    return b[0] if b and module in b[1] else None


def _resolve_call(node, table) -> str | None:
    """Resolve a Call to a primitive category (or None) using the import table."""
    f = node.func
    if isinstance(f, ast.Name):
        if f.id in BUILTIN_EXEC:
            return "exec"
        origin = table.get(f.id)
        return _category_for(f.id, origin) if origin is not None else None
    if isinstance(f, ast.Attribute):
        r = _resolved_module(f)
        if r is None:
            return None
        root, middle, called = r
        origin = table.get(root)
        if origin is None:
            return None
        return _category_for(called, ".".join([origin] + middle))
    return None


def _blob_present(added_strs) -> bool:
    for line in added_strs:
        if _B64_RUN.search(line) or len(line) > LONG_LINE:
            return True
        if len(line) >= ENTROPY_WINDOW and _entropy(line[:ENTROPY_WINDOW]) > ENTROPY_X:
            return True
    return False


@dataclass(frozen=True)
class FileFacts:
    path: str
    lines: tuple
    location_weight: float
    bound_categories: frozenset
    bound_names: frozenset
    imported_modules: frozenset
    blob_present: bool
    syntax_error: bool
    added_strs: tuple


@dataclass(frozen=True)
class DiffFacts:
    files: tuple
    binaries: tuple
    deps: tuple
    maintainer_changed: bool


def _file_facts(fd) -> FileFacts:
    added_strs = tuple(ln for h in fd.hunks for ln in h.added)
    added_lines = {j + 1 for h in fd.hunks for j in range(h.new_range[0], h.new_range[1])}
    lines = (fd.hunks[0].new_range[0] + 1, fd.hunks[-1].new_range[1])
    loc = classify_location(fd.path)
    if fd.new_text is None or not fd.path.endswith((".py", ".pyx", ".pyi")):
        return FileFacts(fd.path, lines, loc, frozenset(), frozenset(), frozenset(), False, False, added_strs)
    try:
        tree = ast.parse(fd.new_text)
    except SyntaxError:
        return FileFacts(fd.path, lines, loc, frozenset(), frozenset(), frozenset(), False, True, added_strs)
    table = _build_import_table(tree)
    cats, names = set(), set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        lo = getattr(node, "lineno", None)
        if lo is None:
            continue
        hi = getattr(node, "end_lineno", None) or lo
        if added_lines.isdisjoint(range(lo, hi + 1)):
            continue
        cat = _resolve_call(node, table)
        if cat:
            cats.add(cat)
            f = node.func
            names.add(f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", ""))
    return FileFacts(fd.path, lines, loc, frozenset(cats), frozenset(names),
                     frozenset(table.values()), _blob_present(added_strs), False, added_strs)


def _normalize_binaries(added_binaries):
    out = []
    for b in added_binaries:
        reason = b.get("reason")
        if not reason and b.get("sha256"):
            reason = "new-binary"        # normalize: a hashed binary with no specific reason -> new-binary
        out.append({**b, "reason": reason})
    return tuple(out)


def _roles_set(meta) -> set:
    return {r.lower() for r in (meta or {}).get("roles") or [] if r}


def build_facts(diff, maintainer_context=None) -> DiffFacts:
    files = tuple(_file_facts(fd) for fd in diff.changed if any(h.added for h in fd.hunks))
    maint = False
    if maintainer_context:
        cur, prior = _roles_set(maintainer_context.get("current")), _roles_set(maintainer_context.get("prior"))
        maint = bool(cur and prior and cur != prior)
    return DiffFacts(files, _normalize_binaries(diff.added_binaries),
                     tuple(diff.added_dep_findings), maint)
