"""How a release's files run (spec A3), for the reviewer: which code runs at build, at interpreter start, on
import, when the user types a command, and when a host tool loads plugins.

Pure, no I/O. Built from the new release's extracted top-level metadata: pyproject.toml (tomllib: [project] and
[tool.setuptools|poetry|flit]), setup.cfg and entry_points.txt (configparser), setup.py (ast: literal setup()
keywords only, anything else is "<computed>"), top_level.txt and .pth lines. Nothing is imported or executed.
Every value here is author-written: the reviewer fences the block as untrusted. Files that do not parse are named
on one capped line, `unparseable: a, b, … (+N more)`, and every field they could declare reads `unknown (<file>
unparseable)` instead of "none"; nothing in here raises on package content."""
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
# backends whose own entry-point tables are parsed here: [tool.poetry.scripts/plugins], [tool.flit.scripts/entrypoints]
_PARSED_BACKENDS = _SETUPTOOLS_BACKENDS + ("poetry.core.masonry.api", "poetry.masonry.api",
                                          "flit_core.buildapi", "flit.buildapi")
# The one kind each top-level metadata file is parsed as, here and in the fetcher (PKG-INFO's Summary). A file is
# never parsed under a second kind: its parsed/unparseable status would contradict itself.
KINDS = {"pyproject.toml": "toml", "setup.cfg": "ini", "PKG-INFO": "pkginfo"}


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


def _cfg_directive(v, what: str) -> str | None:
    """setup.cfg `file:` / `attr:` values are read from elsewhere at build: unknown here, never "none"."""
    v = v.strip() if isinstance(v, str) else ""
    for prefix, src in (("file:", "a file"), ("attr:", "a Python attribute")):
        if v.startswith(prefix):
            return f"unknown (setup.cfg reads {what} from {src})"
    return None


def _join(items, empty="none") -> str:
    items = list(dict.fromkeys(_clip(x) for x in items if str(x).strip()))
    more = len(items) - _MAX_ITEMS
    return ", ".join(items[:_MAX_ITEMS]) + (f", … (+{more} more)" if more > 0 else "") if items else empty


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


_STAR_OK = ("setuptools", "distutils.core")        # `from <these> import *` binds the real setup


def _indirect_setup(tree) -> bool:
    """Cheap detection of common indirect routes to setup(), so the one literal call is not trusted when:
    a call or subscript is called (`getattr(...)(...)`, `fns[k](...)`); getattr/vars/setattr/`__dict__` touch
    setuptools or distutils; a module is imported dynamically; the name `setup` is defined, assigned,
    re-imported from elsewhere or used as a value; a `.setup` attribute is used as a value, assigned or
    deleted; or `*` is imported from a module other than setuptools(.*) / distutils.core.

    Not exhaustive: setup.py is arbitrary code (exec/eval strings, a helper module that patches setuptools,
    distclass=...). exec/eval are deliberately not flagged (exec of a `_version.py` read at build is a
    common version idiom); the block's "none declared literally in setup.py" wording covers what this cannot see."""
    mods = set()                                        # local names bound to setuptools / distutils modules
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods.update((a.asname or a.name).split(".")[0] for a in node.names
                        if a.name.split(".")[0] in _BUILD_MODULES)
        elif isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] in _BUILD_MODULES:
            mods.update(a.asname or a.name for a in node.names if a.name != "setup")
    callee_names = value_names = callee_attrs = value_attrs = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, (ast.Call, ast.Subscript)):
                return True
            if (isinstance(f, ast.Name) and f.id in ("getattr", "vars", "setattr") and node.args
                    and _root(node.args[0]) in mods):
                return True
            callee_names += isinstance(f, ast.Name) and f.id == "setup"
            callee_attrs += isinstance(f, ast.Attribute) and f.attr == "setup"
        elif isinstance(node, ast.Attribute):
            if node.attr in _DYNAMIC_IMPORT or (node.attr == "__dict__" and _root(node.value) in mods):
                return True
            if node.attr == "setup":
                if not isinstance(node.ctx, ast.Load):
                    return True                         # `setuptools.setup = wrapper`, `del setuptools.setup`
                value_attrs += 1
        elif isinstance(node, ast.Name):
            if node.id in _DYNAMIC_IMPORT or (node.id == "setup" and not isinstance(node.ctx, ast.Load)):
                return True
            value_names += node.id == "setup"
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == "setup":
            return True
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            build = isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] in _BUILD_MODULES
            module = getattr(node, "module", None) or ""
            if (isinstance(node, ast.ImportFrom) and any(a.name == "*" for a in node.names)
                    and not (module in _STAR_OK or module.startswith("setuptools."))):
                return True                             # `from helpers import *` may bind any `setup`
            for a in node.names:
                if (a.asname or a.name) == "setup" and not (build and a.name == "setup"):
                    return True                         # `from evil import setup`, `import x as setup`
                if a.name == "setup" and a.asname not in (None, "setup"):
                    return True                         # `from setuptools import setup as s`
    # setup used as a value: `run = setup`, `run = setuptools.setup`, `partial(setuptools.setup, ...)`
    return value_names > callee_names or value_attrs > callee_attrs


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
    {name: target} table. Anything else, an item that is not a string, or a line with no `=` (or an empty
    name) is unknown, never dropped; only blank and `#`/`;` comment lines are skipped."""
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


def _table(v):
    """A TOML entry-point table as written, None when absent, else "<computed>" (never parsed as INI text)."""
    return v if v is None or isinstance(v, dict) else COMPUTED


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


def _entry_points_lines(eps: dict, unknown: list, empty: str) -> tuple[str, str]:
    cmds = [n if n == COMPUTED else f"{n} -> {t}" for g in _COMMAND_GROUPS for n, t in eps.get(g, [])]
    plugins = [f"{g}: {n}" if n == COMPUTED else f"{g}: {n} -> {t}"
               for g, lst in eps.items() if g not in _COMMAND_GROUPS and g != COMPUTED for n, t in lst]
    if COMPUTED in eps:
        cmds.append(f"entry points={COMPUTED}")
        plugins.append(f"entry points={COMPUTED}")
    return _join(cmds + unknown, empty), _join(plugins + unknown, empty)


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
        if parts[-1] == name and (len(parts) == 2 or (len(parts) == 3 and parts[0] == "src")) and \
                parts[-2].endswith(".egg-info"):            # length first: a top-level path has no parts[-2]
            out.append(p)
    return out


def _pth(path, data) -> str:
    text = data.decode("utf-8-sig", errors="replace")       # site decodes .pth as utf-8-sig
    n = sum(1 for ln in text.splitlines() if ln.startswith(("import ", "import\t")))
    return f"{path}: {n} import line{'s' if n != 1 else ''}" if n else f"{path}: paths only"


_BUILD_FILES = ("setup.py", "pyproject.toml", "setup.cfg")
NOT_LITERAL = "none declared literally in setup.py (setup.py runs arbitrary code at build)"
_DYNAMIC_EPS = {"scripts", "gui-scripts", "entry-points"}
_FLIT_BACKENDS = ("flit_core.buildapi", "flit.buildapi")


def build(new_files: dict[str, bytes], too_large=()) -> str:
    """The execution-context block for one release, as plain lines (the reviewer escapes and fences them).

    too_large: paths the extractor recorded as too large to scan (not in new_files). A build file, a .pth or an
    egg-info entry_points.txt among them is unknown, never "absent" or "none". Best effort by construction: while
    setup.py exists, a field it could declare is never a bare "none", because setup.py is arbitrary code."""
    unparseable: list[str] = []
    why: dict[str, str] = {p: "too large" for p in (*_BUILD_FILES, *_egg_info(too_large, "entry_points.txt"))
                           if p in too_large}      # source -> why it is unknown

    def parsed(path, kind):
        if path not in new_files:
            return {}
        m = parse_mapping(new_files[path], kind)
        if m is None:
            unparseable.append(path)
            why[path] = "unparseable"
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
            why["setup.py"] = "unparseable"
    if any(k in pp and not isinstance(pp[k], dict) for k in ("build-system", "project", "tool")) or any(
            k in _dict(pp.get("tool")) and not isinstance(pp["tool"][k], dict)
            for k in ("setuptools", "poetry", "flit")):
        why["pyproject.toml"] = "malformed"

    def kw(name):
        return setup_kw.get(name, COMPUTED if splat else None)

    def unknown(*sources):
        """A field some of whose declaring files could not be read is unknown, never "none"."""
        by_reason: dict[str, list] = {}
        for p, reason in why.items():
            if p in sources or ("entry_points.txt" in sources and p.endswith("/entry_points.txt")):
                by_reason.setdefault(reason, []).append(p)
        return [f"unknown ({_join(ps)} {reason})" for reason, ps in by_reason.items()]

    # while setup.py exists, "nothing declared" only means nothing declared literally
    none = NOT_LITERAL if "setup.py" in new_files else "none"
    bs, project = _dict(pp.get("build-system")), _dict(pp.get("project"))
    st = _dict(_dict(pp.get("tool")).get("setuptools"))
    options = _dict(cfg.get("options"))

    # build
    backend = bs.get("build-backend")
    if ("pyproject.toml" in why or (backend is not None and not (isinstance(backend, str) and backend.strip()))):
        backend, shown = None, "unknown"                    # never the default: the real one is not known
    elif backend is not None:
        backend = backend.strip()
        shown = f"{_clip(backend)} [declared]"
    else:
        backend = "setuptools.build_meta:__legacy__"
        shown = f"{backend} [default]"
    if why.get("setup.py") == "too large":
        setup_py = "unknown (too large to scan)"
    elif "setup.py" not in new_files:
        setup_py = "absent"
    elif backend is None:
        setup_py = "present: runs at build only if the backend is setuptools"
    elif backend in _SETUPTOOLS_BACKENDS:
        setup_py = "present: its top level runs at build"
    else:
        setup_py = f"present: not run by {_clip(backend)} unless the backend calls it"
    # a backend whose own config is not parsed here (another backend, or any in-tree one via backend-path) may
    # declare entry points and generate files we cannot see: its empty fields are qualified, never a bare "none"
    in_tree = bs.get("backend-path") not in (None, [], "")
    ep_none = gen_none = none
    if backend is None or in_tree or backend not in _PARSED_BACKENDS:
        name = ("unknown backend" if backend is None else
                f"in-tree backend {_clip(backend)}" if in_tree else _clip(backend))
        tail = f"; {NOT_LITERAL}" if "setup.py" in new_files else ""
        ep_none = f"none in [project] ({name} may declare its own){tail}"
        gen_none = f"none in scanned files ({name} may generate its own){tail}"
    cmdclass = []
    for v in (kw("cmdclass"), st.get("cmdclass")):
        cmdclass += [COMPUTED] if v == COMPUTED else [str(k) for k in _dict(v)]
    if "cmdclass" in options:
        cmdclass += [ln.split("=", 1)[0].strip() for ln in options["cmdclass"].splitlines()]
    sreq = kw("setup_requires")
    sreq = [COMPUTED] if sreq == COMPUTED else (_strs(sreq) or [])
    v = options.get("setup_requires", "")
    sreq += [d] if (d := _cfg_directive(v, "setup_requires")) else _cfg_list(v)
    bpath = (_strs(bs.get("backend-path")) or []) + unknown("pyproject.toml")
    cmdclass += unknown("pyproject.toml", "setup.py", "setup.cfg")
    sreq += unknown("setup.py", "setup.cfg")
    build_line = (f"build (runs when pip builds or installs from this sdist): backend={shown}; "
                  f"backend-path={_join(bpath)}; setup.py={setup_py}; "
                  f"cmdclass={_join(cmdclass, none)}; setup_requires={_join(sreq, none)}")

    # startup
    pths = [_pth(p, b) for p, b in sorted(new_files.items()) if p.endswith(".pth")]
    pths += [f"unknown ({p} too large to scan)" for p in sorted(too_large) if p.endswith(".pth")]
    startup = ("startup (.pth files; an `import` line runs at every interpreter start if the file is installed "
               f"into site-packages): {_join(pths, gen_none)}")  # setup.py or a backend may write a .pth

    # import
    def declared(setup_name, st_name, cfg_name):
        v = kw(setup_name)
        if v == COMPUTED:
            return COMPUTED
        if (s := _strs(v)) is not None:
            return _join(s, none)
        v = st.get(st_name)
        if isinstance(v, dict):                      # [tool.setuptools.packages.find]
            return None
        if (s := _strs(v)) is not None:
            return _join(s, none)
        v = options.get(cfg_name, "").strip()
        if d := _cfg_directive(v, st_name):
            return d
        return None if not v or v.startswith("find") else _join(_cfg_list(v), none)

    src_unknown = unknown("pyproject.toml", "setup.py", "setup.cfg")
    pkgs = declared("packages", "packages", "packages") or ", ".join(
        src_unknown + [f"auto-discovered: {_join(_discovered(new_files), gen_none)}"])
    mods = declared("py_modules", "py-modules", "py_modules") or _join(src_unknown, gen_none)
    tops = [ln for p in _egg_info(new_files, "top_level.txt")
            for ln in new_files[p].decode("utf-8", errors="replace").split()]
    import_line = (f"import (runs when a program imports the package): packages={pkgs}; py-modules={mods}; "
                   f"top_level.txt={_join(tops) if tops else 'not found in scanned files'}")

    # commands and plugins
    eps: dict = {}
    _add_groups(eps, {"console_scripts": project.get("scripts"), "gui_scripts": project.get("gui-scripts")})
    _add_groups(eps, project.get("entry-points"))
    for tool, scripts, groups in (("poetry", "scripts", "plugins"), ("flit", "scripts", "entrypoints")):
        t = _dict(_dict(pp.get("tool")).get(tool))
        _add_groups(eps, {"console_scripts": t.get(scripts)})
        _add_groups(eps, _table(t.get(groups)))
    _add_groups(eps, kw("entry_points"))
    _add_groups(eps, cfg.get("options.entry_points"))
    cfg_eps = options.get("entry_points", "")
    ep_unknown_cfg = [d] if (d := _cfg_directive(cfg_eps, "entry points")) else []
    if not d:
        _add_groups(eps, cfg_eps.strip() or None)               # INI text inline in [options]
    for p in _egg_info(new_files, "entry_points.txt"):
        _add_groups(eps, parsed(p, "entry_points"))
    flit_paths = []                                     # flit's [tool.flit.metadata] entry-points-file, INI format
    if backend in _FLIT_BACKENDS:
        epf = _dict(_dict(_dict(pp.get("tool")).get("flit")).get("metadata")).get("entry-points-file")
        if epf is None and ("entry_points.txt" in new_files or "entry_points.txt" in too_large):
            epf = "entry_points.txt"                    # old-style flit's default
        if epf is not None and not isinstance(epf, str):
            ep_unknown_cfg.append(f"unknown (flit entry-points-file {COMPUTED})")
        elif epf is not None:
            path = epf.strip().removeprefix("./")
            flit_paths.append(path)
            if path in KINDS or path == "setup.py":                 # setup.py is parsed as Python
                ep_unknown_cfg.append(f"unknown (flit entry-points-file {path} is not an entry-points file)")
            elif path in new_files:
                _add_groups(eps, parsed(path, "entry_points"))
            elif path in too_large:
                why[path] = "too large"
            else:
                ep_unknown_cfg.append(f"unknown (flit entry-points-file {_clip(path)} not in scanned files)")
    ep_unknown = (unknown("pyproject.toml", "setup.py", "setup.cfg", "entry_points.txt", *flit_paths)
                  + ep_unknown_cfg)
    dynamic = project.get("dynamic")
    if isinstance(dynamic, list) and _DYNAMIC_EPS & {d for d in dynamic if isinstance(d, str)}:
        ep_unknown.append("unknown (pyproject.toml marks them dynamic)")   # the backend fills them in at build
    cmds, plugins = _entry_points_lines(eps, ep_unknown, ep_none)

    lines = [build_line, startup, import_line,
             f"commands (console_scripts/gui_scripts; run only when the user types them): {cmds}",
             "plugins (entry points loaded automatically by another tool, e.g. pytest11 runs on every pytest "
             f"run): {plugins}"]
    lines += [f"{p}: unknown (too large to scan)" for p in _BUILD_FILES if why.get(p) == "too large"]   # at most 3
    if unparseable:                                     # one line, however many files: bounded
        lines.append(f"unparseable: {_join(unparseable)}")
    lines.append("other: files under tests/ docs/ examples/ are not imported by the package unless listed above")
    return "\n".join(ln if len(ln) <= _MAX_LINE else ln[:_MAX_LINE] + "…" for ln in lines)
