"""How a release's files run (spec A3), for the reviewer: which code runs at build, at interpreter start, on
import, when the user types a command, and when a host tool loads plugins.

Pure, no I/O. Built from the new release's extracted top-level metadata: pyproject.toml (tomllib), setup.cfg
and entry_points.txt (configparser), setup.py (ast: literal setup() keywords only, anything else is
"<computed>"), top_level.txt and .pth lines. Nothing is imported or executed. Every value here is
author-written: the reviewer fences the block as untrusted. Files that do not parse are named on one capped
line, `unparseable: a, b, … (+N more)`, and every field they could declare reads `unknown (<file> unparseable)`
instead of "none"; nothing in here raises on package content."""
import ast
import configparser
import email.parser
import json
import tomllib

_PARSE_ERRORS = (ValueError, SyntaxError, RecursionError, MemoryError, UnicodeDecodeError,
                 configparser.Error, tomllib.TOMLDecodeError)
_MAX_ITEMS = 20
_MAX_LINE = 2_000
_LIT_DEPTH = 4          # deeper literals in setup() are shown as "<computed>"
COMPUTED = "<computed>"
_SETUPTOOLS_BACKENDS = ("setuptools.build_meta", "setuptools.build_meta:__legacy__")


def _ini(text: str, delimiters=("=", ":")) -> dict:
    # default_section: no header can contain a newline, so an author's [DEFAULT] is an ordinary section and its
    # keys never leak into every other section.
    cp = configparser.ConfigParser(interpolation=None, delimiters=delimiters, default_section="\n")
    cp.optionxform = str                                # keep entry-point names' case
    cp.read_string(text)
    return {s: dict(cp[s]) for s in cp.sections()}


def parse_mapping(data: bytes, kind: str) -> dict | None:
    """The one parser for author-written structured files (npm #25 parity). kind: toml | ini | entry_points
    | pkginfo | json. A UTF-8 BOM is accepted; a top level that is not a mapping is {}; a parse failure is
    None (named on the block's `unparseable: a, b, …` line). Never raises on content."""
    try:
        text = data.decode("utf-8-sig")
        if kind == "toml":
            out = tomllib.loads(text)
        elif kind == "ini":
            out = _ini(text)
        elif kind == "entry_points":
            out = _ini(text, delimiters=("=",))
        elif kind == "pkginfo":
            out = dict(email.parser.HeaderParser().parsestr(text).items())
        elif kind == "json":
            out = json.loads(text)
        else:
            raise ValueError(kind)
    except _PARSE_ERRORS:
        return None
    return out if isinstance(out, dict) else {}


def _clip(s, n=200) -> str:
    s = " ".join(str(s).split())                        # one line: nothing here may start a line of its own
    return s if len(s) <= n else s[:n] + "…"


def _dict(v) -> dict:
    return v if isinstance(v, dict) else {}


def _strs(v) -> list[str] | None:
    """A list of strings (a non-string item shows as "<computed>"), a lone string, or None when the field is
    absent or of the wrong type."""
    if isinstance(v, str):
        return [v]
    if isinstance(v, (list, tuple)):
        return [x if isinstance(x, str) else COMPUTED for x in v]
    return None


def _cfg_list(v) -> list[str]:
    """A setup.cfg list value: comma- or newline-separated."""
    return [x.strip() for x in str(v).replace(";", ",").replace("\n", ",").split(",") if x.strip()]


def _join(items) -> str:
    items = list(dict.fromkeys(_clip(x) for x in items if str(x).strip()))
    more = len(items) - _MAX_ITEMS
    return ", ".join(items[:_MAX_ITEMS]) + (f", … (+{more} more)" if more > 0 else "") if items else "none"


# ---- setup.py: literal keywords of the setup() call ----

def _lit(node, depth=0):
    if depth > _LIT_DEPTH:
        return COMPUTED
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return [_lit(e, depth + 1) for e in node.elts]
    if isinstance(node, ast.Dict):
        if not all(isinstance(k, ast.Constant) for k in node.keys):     # a None key is a ** splat
            return COMPUTED
        return {k.value: _lit(v, depth + 1) for k, v in zip(node.keys, node.values)}
    return COMPUTED


_BUILD_MODULES = ("setuptools", "distutils")
_DYNAMIC_IMPORT = {"__import__", "import_module"}


def _root(node):
    while isinstance(node, ast.Attribute):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _indirect_setup(tree) -> bool:
    """True when setup() may be reached some way other than the one literal call we read: a called call or
    subscript (`getattr(...)(...)`, `fns[k](...)`), getattr/vars/`__dict__` on setuptools or distutils, a dynamic
    import, or the name `setup` defined, assigned, imported from elsewhere or passed around as a value."""
    mods = set()                                        # local names bound to setuptools / distutils modules
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods.update((a.asname or a.name).split(".")[0] for a in node.names
                        if a.name.split(".")[0] in _BUILD_MODULES)
        elif isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] in _BUILD_MODULES:
            mods.update(a.asname or a.name for a in node.names if a.name != "setup")
    callee_names = value_names = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, (ast.Call, ast.Subscript)):
                return True
            if (isinstance(f, ast.Name) and f.id in ("getattr", "vars") and node.args
                    and _root(node.args[0]) in mods):
                return True
            callee_names += isinstance(f, ast.Name) and f.id == "setup"
        elif isinstance(node, ast.Attribute):
            if node.attr in _DYNAMIC_IMPORT or (node.attr == "__dict__" and _root(node.value) in mods):
                return True
        elif isinstance(node, ast.Name):
            if node.id in _DYNAMIC_IMPORT or (node.id == "setup" and not isinstance(node.ctx, ast.Load)):
                return True
            value_names += node.id == "setup"
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == "setup":
            return True
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            build = isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] in _BUILD_MODULES
            for a in node.names:
                if (a.asname or a.name) == "setup" and not (build and a.name == "setup"):
                    return True                         # `from evil import setup`, `import x as setup`
                if a.name == "setup" and a.asname not in (None, "setup"):
                    return True                         # `from setuptools import setup as s`
    return value_names > callee_names                   # `run = setup`: setup used as a value


def _setup_kwargs(tree) -> tuple[dict, bool]:
    """(literal keywords of the setup() call, whether any keyword it lacks may still be computed).

    Only a single `setup(...)` / `x.setup(...)` call is read. None, several (a decoy under `if False:` can
    precede the real call), or any indirect route to setup (_indirect_setup): every keyword is unknown."""
    calls = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            if (f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None) == "setup":
                calls.append(node)
    if len(calls) != 1 or _indirect_setup(tree):
        return {}, True
    return ({k.arg: _lit(k.value) for k in calls[0].keywords if k.arg is not None},
            any(k.arg is None for k in calls[0].keywords))


# ---- entry points ----

_UNKNOWN_EP = (COMPUTED, "")      # an entry point whose name or target is not statically known


def _ep_lines(v) -> list[tuple[str, str]]:
    """Entry points of one group, from a list of "name = target" strings, one INI-style string, or a
    {name: target} table. Anything else, or an item that is not a string, is unknown: never "none"."""
    if isinstance(v, dict):
        return [(str(k), t) if isinstance(t, str) else _UNKNOWN_EP for k, t in v.items()]
    if isinstance(v, str):
        v = v.splitlines()
    if not isinstance(v, (list, tuple)):
        return [_UNKNOWN_EP]
    out = []
    for line in v:
        if isinstance(line, str) and (not line.strip() or line.lstrip().startswith(("#", ";"))):
            continue                                    # blank or comment line of an INI-style value
        if not isinstance(line, str) or line == COMPUTED or "=" not in line or not line.split("=", 1)[0].strip():
            out.append(_UNKNOWN_EP)                     # never dropped silently
        else:
            name, target = line.split("=", 1)
            out.append((name.strip(), target.strip()))
    return out


def _add_groups(eps: dict, groups) -> None:
    """Merge one source's {group: entries} into eps. None means the source has no entry points; anything
    that is not statically a table (computed, wrong type, unparseable INI text) is unknown."""
    if groups is None:
        return
    if isinstance(groups, str) and groups != COMPUTED:      # setup.py may pass the INI text itself
        groups = parse_mapping(groups.encode("utf-8", "surrogatepass"), "entry_points")
    if not isinstance(groups, dict):
        eps.setdefault(COMPUTED, [])
        return
    for group, v in groups.items():
        if not isinstance(group, str):
            eps.setdefault(COMPUTED, [])                # a group we cannot name: unknown, not dropped
        elif v is not None:
            eps.setdefault(group.strip(), []).extend(_ep_lines(v))


_COMMAND_GROUPS = ("console_scripts", "gui_scripts")


def _entry_points_lines(eps: dict, unknown: list) -> tuple[str, str]:
    cmds = [n if n == COMPUTED else f"{n} -> {t}" for g in _COMMAND_GROUPS for n, t in eps.get(g, [])]
    plugins = [f"{g}: {n}" if n == COMPUTED else f"{g}: {n} -> {t}"
               for g, lst in eps.items() if g not in _COMMAND_GROUPS and g != COMPUTED for n, t in lst]
    if COMPUTED in eps:
        cmds.append(f"entry points={COMPUTED}")
        plugins.append(f"entry points={COMPUTED}")
    return _join(cmds + unknown), _join(plugins + unknown)


# ---- discovery ----

_NOT_PACKAGES = {"tests", "test", "docs", "doc", "examples", "example", "benchmarks", "scripts", "tools"}


def _discovered(files) -> list[str]:
    pkgs = []
    for p in sorted(files):
        parts = p.split("/")
        if parts[-1] != "__init__.py":
            continue
        if len(parts) == 2 or (len(parts) == 3 and parts[0] == "src"):
            if parts[-2] not in _NOT_PACKAGES:
                pkgs.append(parts[-2])
    return pkgs


def _egg_info(files, name) -> list[str]:
    """`<x>.egg-info/<name>` at the top level or under src/."""
    out = []
    for p in sorted(files):
        parts = p.split("/")
        if parts[-1] == name and parts[-2].endswith(".egg-info") and (len(parts) == 2 or
                                                                      (len(parts) == 3 and parts[0] == "src")):
            out.append(p)
    return out


def _pth(path, data) -> str:
    text = data.decode("utf-8-sig", errors="replace")       # site decodes .pth as utf-8-sig
    n = sum(1 for ln in text.splitlines() if ln.startswith(("import ", "import\t")))
    return f"{path}: {n} import line{'s' if n != 1 else ''}" if n else f"{path}: paths only"


def build(new_files: dict[str, bytes]) -> str:
    """The execution-context block for one release, as plain lines (the reviewer escapes and fences them)."""
    unparseable: list[str] = []

    def parsed(path, kind):
        if path not in new_files:
            return {}
        m = parse_mapping(new_files[path], kind)
        if m is None:
            unparseable.append(path)
            return {}
        return m

    pp = parsed("pyproject.toml", "toml")
    cfg = parsed("setup.cfg", "ini")
    setup_kw, splat = {}, False
    if "setup.py" in new_files:
        try:
            setup_kw, splat = _setup_kwargs(ast.parse(new_files["setup.py"]))   # bytes: BOM and coding cookie honoured
        except _PARSE_ERRORS:
            unparseable.append("setup.py")

    def kw(name):
        return setup_kw.get(name, COMPUTED if splat else None)

    def unknown(*sources):
        """A field some of whose declaring files failed to parse is unknown, never "none"."""
        bad = [p for p in unparseable
               if p in sources or ("entry_points.txt" in sources and p.endswith("/entry_points.txt"))]
        return [f"unknown ({_join(bad)} unparseable)"] if bad else []

    bs, project = _dict(pp.get("build-system")), _dict(pp.get("project"))
    st = _dict(_dict(pp.get("tool")).get("setuptools"))
    options = _dict(cfg.get("options"))

    # build
    backend = bs.get("build-backend")
    if ("pyproject.toml" in unparseable or not isinstance(pp.get("build-system", {}), dict)
            or (backend is not None and not (isinstance(backend, str) and backend.strip()))):
        backend, shown = None, "unknown"                    # never the default: the real one is not known
    elif backend is not None:
        backend = backend.strip()
        shown = f"{_clip(backend)} [declared]"
    else:
        backend = "setuptools.build_meta:__legacy__"
        shown = f"{backend} [default]"
    if "setup.py" not in new_files:
        setup_py = "absent"
    elif backend is None:
        setup_py = "present: runs at build only if the backend is setuptools"
    elif backend in _SETUPTOOLS_BACKENDS:
        setup_py = "present: its top level runs at build"
    else:
        setup_py = f"present: not run by {_clip(backend)} unless the backend calls it"
    cmdclass = []
    for v in (kw("cmdclass"), st.get("cmdclass")):
        cmdclass += [COMPUTED] if v == COMPUTED else [str(k) for k in _dict(v)]
    if "cmdclass" in options:
        cmdclass += [ln.split("=", 1)[0].strip() for ln in options["cmdclass"].splitlines()]
    sreq = kw("setup_requires")
    sreq = [COMPUTED] if sreq == COMPUTED else (_strs(sreq) or [])
    sreq += _cfg_list(options.get("setup_requires", ""))
    bpath = (_strs(bs.get("backend-path")) or []) + unknown("pyproject.toml")
    cmdclass += unknown("pyproject.toml", "setup.py", "setup.cfg")
    sreq += unknown("setup.py", "setup.cfg")
    build_line = (f"build (runs when pip builds or installs from this sdist): backend={shown}; "
                  f"backend-path={_join(bpath)}; setup.py={setup_py}; "
                  f"cmdclass={_join(cmdclass)}; setup_requires={_join(sreq)}")

    # startup
    pths = [_pth(p, b) for p, b in sorted(new_files.items()) if p.endswith(".pth")]
    startup = ("startup (.pth files; an `import` line runs at every interpreter start if the file is installed "
               f"into site-packages): {_join(pths)}")

    # import
    def declared(setup_name, st_name, cfg_name):
        v = kw(setup_name)
        if v == COMPUTED:
            return COMPUTED
        if (s := _strs(v)) is not None:
            return _join(s)
        v = st.get(st_name)
        if isinstance(v, dict):                      # [tool.setuptools.packages.find]
            return None
        if (s := _strs(v)) is not None:
            return _join(s)
        v = options.get(cfg_name, "").strip()
        return None if not v or v.startswith("find") else _join(_cfg_list(v))

    src_unknown = unknown("pyproject.toml", "setup.py", "setup.cfg")
    pkgs = declared("packages", "packages", "packages") or ", ".join(
        src_unknown + [f"auto-discovered: {_join(_discovered(new_files))}"])
    mods = declared("py_modules", "py-modules", "py_modules") or _join(src_unknown)
    tops = [ln for p in _egg_info(new_files, "top_level.txt")
            for ln in new_files[p].decode("utf-8", errors="replace").split()]
    import_line = (f"import (runs when a program imports the package): packages={pkgs}; py-modules={mods}; "
                   f"top_level.txt={_join(tops) if tops else 'not found in scanned files'}")

    # commands and plugins
    eps: dict = {}
    _add_groups(eps, {"console_scripts": project.get("scripts"), "gui_scripts": project.get("gui-scripts")})
    _add_groups(eps, project.get("entry-points"))
    _add_groups(eps, kw("entry_points"))
    _add_groups(eps, cfg.get("options.entry_points"))
    for p in _egg_info(new_files, "entry_points.txt"):
        _add_groups(eps, parsed(p, "entry_points"))
    cmds, plugins = _entry_points_lines(eps, unknown("pyproject.toml", "setup.py", "setup.cfg", "entry_points.txt"))

    lines = [build_line, startup, import_line,
             f"commands (console_scripts/gui_scripts; run only when the user types them): {cmds}",
             "plugins (entry points loaded automatically by another tool, e.g. pytest11 runs on every pytest "
             f"run): {plugins}"]
    if unparseable:                                     # one line, however many files: bounded
        lines.append(f"unparseable: {_join(unparseable)}")
    lines.append("other: files under tests/ docs/ examples/ are not imported by the package unless listed above")
    return "\n".join(ln if len(ln) <= _MAX_LINE else ln[:_MAX_LINE] + "…" for ln in lines)
