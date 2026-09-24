"""execctx: how a release's files run, parsed statically from its build metadata (spec A3).

tomllib / configparser / ast / email.parser only: nothing is imported or executed. One parser helper for every
author-written structured file (npm #25 parity): it accepts a BOM, maps a non-mapping to {}, and never raises;
files that do not parse are named on one capped line, `unparseable: a, b, … (+N more)`."""
import pytest

from pydiffwatch import execctx

PYPROJECT = b"""\
[build-system]
requires = ["setuptools>=61", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "acme-tools"
version = "0.5.0"

[project.scripts]
acme-install-hook = "acme_tools.hooks:install"

[project.entry-points.pytest11]
acme = "acme_tools.pytest_plugin"
"""

CUSTOM = b"""\
[build-system]
requires = []
build-backend = "backend"
backend-path = ["_build"]

[project]
name = "acme-tools"
version = "0.5.0"
"""

SRC = {"src/acme_tools/__init__.py": b"", "src/acme_tools/hooks.py": b"x = 1\n"}


def _files(pyproject=PYPROJECT, **extra):
    return {"pyproject.toml": pyproject, **SRC, **extra}


def test_a_custom_backend_and_its_backend_path_are_listed():
    ctx = execctx.build({"pyproject.toml": CUSTOM, "_build/backend.py": b"", "setup.py": b"setup()\n"})
    assert "backend=backend [declared]" in ctx and "backend-path=_build" in ctx
    assert "setup.py=present: not run by backend unless the backend calls it" in ctx


def test_no_build_backend_is_the_setuptools_legacy_default_and_setup_py_runs():
    ctx = execctx.build({"setup.py": b"from setuptools import setup\nsetup(name='a')\n"})
    assert "backend=setuptools.build_meta:__legacy__ [default]" in ctx
    assert "setup.py=present: its top level runs at build" in ctx


def test_console_scripts_are_user_typed_and_plugin_groups_are_automatic():
    ctx = execctx.build(_files())
    lines = ctx.split("\n")
    cmd = next(ln for ln in lines if ln.startswith("commands"))
    plug = next(ln for ln in lines if ln.startswith("plugins"))
    assert "run only when the user types them" in cmd and "acme-install-hook -> acme_tools.hooks:install" in cmd
    assert "loaded automatically" in plug and "pytest11: acme -> acme_tools.pytest_plugin" in plug
    assert "pytest11" not in cmd and "acme-install-hook" not in plug


def test_entry_points_from_setup_py_setup_cfg_and_entry_points_txt():
    setup_py = (b"from setuptools import setup\nsetup(name='a', cmdclass={'build_py': BuildPy}, "
                b"setup_requires=['cython'], packages=['acme'],\n"
                b"      entry_points={'console_scripts': ['a-cli = acme.cli:main'],\n"
                b"                    'flake8.extension': ['ACM = acme.lint:Checker']})\n")
    setup_cfg = (b"[options]\npackages = find:\npy_modules = single\n"
                 b"[options.entry_points]\ngui_scripts =\n    a-gui = acme.gui:run\n")
    ep_txt = b"[console_scripts]\na-txt = acme.txt:main\n\n[pytest11]\nacme = acme.plugin\n"
    ctx = execctx.build({"setup.py": setup_py, "setup.cfg": setup_cfg,
                         "acme.egg-info/entry_points.txt": ep_txt, "acme.egg-info/top_level.txt": b"acme\n"})
    assert "cmdclass=build_py" in ctx and "setup_requires=cython" in ctx
    assert "packages=acme" in ctx and "py-modules=single" in ctx and "top_level.txt=acme" in ctx
    cmd = next(ln for ln in ctx.split("\n") if ln.startswith("commands"))
    for s in ("a-cli -> acme.cli:main", "a-gui -> acme.gui:run", "a-txt -> acme.txt:main"):
        assert s in cmd
    plug = next(ln for ln in ctx.split("\n") if ln.startswith("plugins"))
    assert "flake8.extension: ACM -> acme.lint:Checker" in plug and "pytest11: acme -> acme.plugin" in plug


def test_computed_setup_keywords_are_shown_as_computed():
    ctx = execctx.build({"setup.py": b"from setuptools import setup\n"
                                     b"setup(cmdclass=get_cmds(), packages=find_packages(), **extra)\n"})
    assert "cmdclass=<computed>" in ctx and "packages=<computed>" in ctx
    assert "setup_requires=<computed>" in ctx          # **extra may carry it


def test_pth_import_lines_are_startup_code():
    ctx = execctx.build({"acme.pth": b"\xef\xbb\xbfimport acme._boot\n./vendor\n",
                         "paths.pth": b"./lib\n"})
    start = next(ln for ln in ctx.split("\n") if ln.startswith("startup"))
    assert "every interpreter start" in start
    assert "acme.pth: 1 import line" in start and "paths.pth: paths only" in start


def test_packages_are_auto_discovered_when_not_declared():
    ctx = execctx.build(_files())
    assert "packages=auto-discovered: acme_tools" in ctx


def test_only_top_level_metadata_is_read():
    ctx = execctx.build({"vendor/x/pyproject.toml": CUSTOM, "vendor/x/setup.py": b"setup()\n"})
    assert "backend=setuptools.build_meta:__legacy__ [default]" in ctx and "setup.py=absent" in ctx


# ---- never raise: malformed input is named on the `unparseable:` line ----

_DEEP_TOML = b"a = " + b"[" * 10_000 + b"]" * 10_000 + b"\n"
_DEEP_INI = b"[options]\npackages = " + b"[" * 10_000 + b"\n"


@pytest.mark.parametrize("name,data", [
    ("pyproject.toml", b"[build-system\nbuild-backend = "),
    ("pyproject.toml", _DEEP_TOML),
    ("pyproject.toml", b"\xff\xfe not utf-8"),
    ("setup.cfg", b"no section header\nx = 1\n"),
    ("setup.cfg", b"[a]\nx = 1\n[a]\ny = 2\n"),
    ("setup.py", b"setup(name='a'\n"),
    ("setup.py", b"x = " + b"(" * 10_000 + b")" * 10_000 + b"\n"),
    ("setup.py", b"x = " + b"-" * 100_000 + b"1\n"),
    ("setup.py", b"setup(name='\x00')\n"),
    ("acme.egg-info/entry_points.txt", b"console_scripts\n a = b:c\n"),
])
def test_malformed_input_is_unparseable_never_an_exception(name, data):
    ctx = execctx.build({name: data})
    assert f"unparseable: {name}" in ctx.split("\n")


def test_deep_but_valid_ini_is_just_text():
    assert "unparseable" not in execctx.build({"setup.cfg": _DEEP_INI})


def test_deeply_nested_setup_literals_are_computed_not_a_crash():
    nested = b"setup(packages=" + b"[" * 150 + b"'a'" + b"]" * 150 + b")\n"
    ctx = execctx.build({"setup.py": nested})
    assert "unparseable" not in ctx and "packages=<computed>" in ctx


# ---- the one parser helper (npm #25 parity): BOM, broken, non-mapping, wrong-typed ----

@pytest.mark.parametrize("kind,good", [
    ("toml", b'[project]\nname = "a"\n'),
    ("ini", b"[metadata]\nname = a\n"),
    ("entry_points", b"[console_scripts]\na = b:c\n"),
    ("pkginfo", b"Metadata-Version: 2.1\nName: a\nSummary: s\n"),
    ("json", b'{"name": "a"}'),
])
def test_parser_accepts_a_utf8_bom(kind, good):
    assert execctx.parse_mapping(b"\xef\xbb\xbf" + good, kind) == execctx.parse_mapping(good, kind) != {}


@pytest.mark.parametrize("kind,broken", [
    ("toml", b"a = = 1"),
    ("toml", _DEEP_TOML),
    ("ini", b"x = 1\n"),
    ("entry_points", b"[console_scripts\n"),
    ("pkginfo", b"\xff\xfe\x00bad"),
    ("json", b"{"),
    ("json", b"[" * 10_000 + b"]" * 10_000),
])
def test_parser_returns_none_on_a_broken_file(kind, broken):
    assert execctx.parse_mapping(broken, kind) is None


@pytest.mark.parametrize("kind,data", [("json", b"[1, 2]"), ("json", b'"s"'), ("json", b"5"), ("json", b"null")])
def test_parser_returns_an_empty_mapping_for_a_non_mapping(kind, data):
    assert execctx.parse_mapping(data, kind) == {}


def test_pkginfo_is_parsed_as_headers():
    m = execctx.parse_mapping(b"Metadata-Version: 2.1\nName: acme\nSummary: tools\n\nlong body", "pkginfo")
    assert m["Name"] == "acme" and m["Summary"] == "tools"


@pytest.mark.parametrize("files", [
    {"pyproject.toml": b"build-system = 5\nproject = 5\ntool = 5\n"},
    {"pyproject.toml": b"[build-system]\nbuild-backend = 5\nbackend-path = \"x\"\n"},
    {"pyproject.toml": b"[project]\nscripts = 5\ngui-scripts = [1]\nentry-points = 5\n"},
    {"pyproject.toml": b"[project.entry-points]\npytest11 = 5\ng = {a = 5}\n"},
    {"pyproject.toml": b"[tool.setuptools]\npackages = 5\npy-modules = {a = 1}\ncmdclass = [1]\n"},
    {"pyproject.toml": b"[tool]\nsetuptools = 5\n"},
    {"setup.cfg": b"[options]\npackages =\ncmdclass = junk\n[options.entry_points]\nconsole_scripts = junk\n"},
    {"setup.py": b"setup(entry_points=5, cmdclass=[1], packages=5, setup_requires={'a': 1})\n"},
    {"setup.py": b"setup(entry_points={'console_scripts': 5, 5: ['a=b'], 'g': 'x = y:z'})\n"},
    {"acme.egg-info/entry_points.txt": b"[console_scripts]\nnovalue\n"},
    {"acme.egg-info/top_level.txt": b"\xff\xfe"},
    {"x.pth": b"\xff\xfeimport os\n"},
])
def test_wrong_typed_fields_never_raise(files):
    ctx = execctx.build(files)
    assert ctx.startswith("build ")


def test_scripts_of_the_wrong_type_are_not_reported_as_none():
    ctx = execctx.build({"pyproject.toml": b"[project]\nscripts = 5\n"})
    assert "commands (console_scripts/gui_scripts; run only when the user types them): <computed>" in ctx.split("\n")


# ---- fix round 1: unknown is never rendered as "none" ----

def _line(ctx, prefix):
    return next(ln for ln in ctx.split("\n") if ln.startswith(prefix))


def test_many_unparseable_files_fold_into_one_capped_line():
    files = {f"e{i:04d}.egg-info/entry_points.txt": b"no section\n" for i in range(1990)}
    ctx = execctx.build(files)
    bad = [ln for ln in ctx.split("\n") if "unparseable" in ln]
    assert len(bad) == 1 and bad[0].startswith("unparseable: e0000.egg-info/entry_points.txt, ")
    assert "(+1970 more)" in bad[0] and len(ctx) < 10_000


def test_an_ini_string_entry_points_in_setup_py_is_parsed():
    ctx = execctx.build({"setup.py": b"from setuptools import setup\nsetup(name='a', entry_points='''"
                                     b"[console_scripts]\\nfoo = a.cli:main\\n[pytest11]\\nx = a.plug''')\n"})
    assert "foo -> a.cli:main" in _line(ctx, "commands") and "pytest11: x -> a.plug" in _line(ctx, "plugins")


def test_an_unparseable_ini_string_entry_points_is_computed():
    ctx = execctx.build({"setup.py": b"setup(entry_points='console_scripts\\nfoo = a:b')\n"})
    assert "<computed>" in _line(ctx, "commands") and "<computed>" in _line(ctx, "plugins")


def test_a_computed_group_value_is_computed_not_none():
    ctx = execctx.build({"setup.py": b"setup(entry_points={'console_scripts': get_scripts(), 'pytest11': X})\n"})
    assert _line(ctx, "commands").endswith(": <computed>")
    assert "pytest11: <computed>" in _line(ctx, "plugins")


def test_a_computed_item_in_a_group_list_is_computed():
    ctx = execctx.build({"setup.py": b"setup(entry_points={'console_scripts': ['foo=a:main', NAME + '=a:b']})\n"})
    assert "foo -> a:main" in _line(ctx, "commands") and "<computed>" in _line(ctx, "commands")


def test_a_decoy_setup_call_makes_every_keyword_computed():
    ctx = execctx.build({"setup.py": b"if False:\n    setup(name='x')\ndef main():\n"
                                     b"    setuptools.setup(cmdclass={'install': Evil})\nmain()\n"})
    assert "cmdclass=<computed>" in ctx and "packages=<computed>" in ctx
    assert "<computed>" in _line(ctx, "commands") and "<computed>" in _line(ctx, "plugins")


def test_an_aliased_setup_makes_every_keyword_computed():
    ctx = execctx.build({"setup.py": b"from setuptools import setup as s\ns(cmdclass={'install': Evil})\n"})
    assert "cmdclass=<computed>" in ctx and "setup_requires=<computed>" in ctx
    assert "<computed>" in _line(ctx, "commands")


def test_a_setup_py_without_a_setup_call_is_computed():
    ctx = execctx.build({"setup.py": b"from mylib import build\nbuild()\n"})
    assert "cmdclass=<computed>" in ctx and "<computed>" in _line(ctx, "commands")


def test_a_single_plain_setup_call_is_still_read_literally():
    ctx = execctx.build({"setup.py": b"import setuptools\nsetuptools.setup(cmdclass={'build_py': B})\n"})
    assert "cmdclass=build_py" in ctx and f"setup_requires={NOT_LITERAL}" in ctx


def test_missing_top_level_txt_is_not_claimed_absent():
    ctx = execctx.build(_files())
    assert "top_level.txt=not found in scanned files" in ctx and "absent" not in _line(ctx, "import")


def test_an_in_tree_backend_named_like_setuptools_is_not_setuptools():
    ctx = execctx.build({"pyproject.toml": b"[build-system]\nrequires=[]\nbuild-backend='setuptools_evil'\n"
                                           b"backend-path=['.']\n", "setup.py": b"setup()\n"})
    assert "setup.py=present: not run by setuptools_evil unless the backend calls it" in ctx
    for legacy in (b"setuptools.build_meta", b"setuptools.build_meta:__legacy__"):
        ctx = execctx.build({"pyproject.toml": b"[build-system]\nbuild-backend='" + legacy + b"'\n",
                             "setup.py": b"setup()\n"})
        assert "setup.py=present: its top level runs at build" in ctx


@pytest.mark.parametrize("pp", [b"[build-system\nbuild-backend='flit_core.buildapi'", b"build-system = 5\n",
                                b"[build-system]\nbuild-backend = 5\n"])
def test_a_broken_or_wrong_typed_pyproject_has_an_unknown_backend(pp):
    ctx = execctx.build({"pyproject.toml": pp, "setup.py": b"setup()\n"})
    assert "backend=unknown" in ctx and "[default]" not in ctx
    assert "its top level runs at build" not in ctx


def test_a_pyproject_without_build_backend_is_the_default():
    ctx = execctx.build({"pyproject.toml": b"[build-system]\nrequires=['setuptools']\n"})
    assert "backend=setuptools.build_meta:__legacy__ [default]" in ctx


def test_default_section_keys_do_not_leak_into_other_sections():
    cfg = b"[DEFAULT]\nzz = 1\n[options.entry_points]\nconsole_scripts =\n    foo = a:main\n"
    assert execctx.parse_mapping(cfg, "ini")["options.entry_points"] == {"console_scripts": "\nfoo = a:main"}
    ctx = execctx.build({"setup.cfg": cfg})
    assert "zz" not in _line(ctx, "plugins") and "foo -> a:main" in _line(ctx, "commands")


# ---- fix round 2: every indirect setup() makes every keyword computed ----

def _all_computed(ctx):
    return ("cmdclass=<computed>" in ctx and "setup_requires=<computed>" in ctx
            and "<computed>" in _line(ctx, "commands") and "<computed>" in _line(ctx, "plugins"))


def test_a_decoy_plus_a_getattr_setup_is_computed():
    ctx = execctx.build({"setup.py": b"import setuptools\nif False:\n    setuptools.setup(name='x')\n"
                                     b"getattr(setuptools, 'se'+'tup')(entry_points={'pytest11': ['p = evil']})\n"})
    assert _all_computed(ctx)


def test_a_called_call_or_subscript_is_computed():
    for src in (b"from setuptools import setup\nsetup(name='a')\nmk()(entry_points={'pytest11': ['p = e']})\n",
                b"from setuptools import setup\nsetup(name='a')\nfns['s'](entry_points={'pytest11': ['p = e']})\n"):
        assert _all_computed(execctx.build({"setup.py": src})), src


def test_getattr_dict_or_import_on_setuptools_is_computed():
    for src in (b"import setuptools\nsetuptools.setup(name='a')\nf = getattr(setuptools, 'setup')\n",
                b"import setuptools as st\nst.setup(name='a')\nf = st.__dict__['setup']\n",
                b"from distutils import core\ncore.setup(name='a')\nf = vars(core)\n",
                b"import setuptools\nsetuptools.setup(name='a')\nm = __import__('setup' + 'tools')\n"):
        assert _all_computed(execctx.build({"setup.py": src})), src


def test_a_local_def_or_assignment_of_setup_is_computed():
    for src in (b"import setuptools\ndef setup(**kw):\n    kw['entry_points'] = {'pytest11': ['p = evil']}\n"
                b"    return setuptools.__dict__['se'+'tup'](**kw)\nsetup(name='x')\n",
                b"import setuptools\nsetup = make_setup()\nsetup(name='x')\n",
                b"from evil import setup\nsetup(name='x')\n",
                b"from setuptools import setup\nrun = setup\nrun(name='x')\nsetup(name='y')\n"):
        assert _all_computed(execctx.build({"setup.py": src})), src


def test_plain_setuptools_and_distutils_setup_calls_are_still_literal():
    for src in (b"from setuptools import setup\nsetup(cmdclass={'build_py': B})\n",
                b"import setuptools\nsetuptools.setup(cmdclass={'build_py': B})\n",
                b"from distutils.core import setup\nsetup(cmdclass={'build_py': B})\n"):
        assert "cmdclass=build_py" in execctx.build({"setup.py": src}), src


# ---- fix round 2: a source that failed to parse makes its fields unknown, never "none" ----

def test_an_unparseable_pyproject_makes_its_fields_unknown():
    ctx = execctx.build({"pyproject.toml": b"[project\nname='x'\n[project.entry-points.pytest11]\np='evil'\n"})
    u = "unknown (pyproject.toml unparseable)"
    assert f"commands (console_scripts/gui_scripts; run only when the user types them): {u}" in ctx
    assert _line(ctx, "plugins").endswith(u) and f"backend-path={u}" in ctx and f"cmdclass={u}" in ctx
    assert f"py-modules={u}" in ctx and "setup_requires=none" in ctx      # pyproject cannot declare setup_requires


def test_an_unparseable_setup_py_makes_its_fields_unknown():
    ctx = execctx.build({"setup.py": b"from setuptools import setup\nsetup(name='x', entry_points={'pytest11': ['p = e']}\n",
                         "a.egg-info/entry_points.txt": b"[console_scripts]\nc = a:main\n"})
    u = "unknown (setup.py unparseable)"
    assert _line(ctx, "commands").endswith(f"c -> a:main, {u}") and _line(ctx, "plugins").endswith(u)
    assert f"cmdclass={u}" in ctx and f"setup_requires={u}" in ctx and f"py-modules={u}" in ctx
    assert "backend-path=none" in ctx                                    # only pyproject declares it


def test_an_unparseable_setup_cfg_and_entry_points_txt_make_their_fields_unknown():
    ctx = execctx.build({"setup.cfg": b"no header\n", "a.egg-info/entry_points.txt": b"broken\n"})
    assert _line(ctx, "commands").endswith("unknown (setup.cfg, a.egg-info/entry_points.txt unparseable)")
    assert "setup_requires=unknown (setup.cfg unparseable)" in ctx and "cmdclass=unknown (setup.cfg unparseable)" in ctx


def test_an_entry_point_item_without_equals_is_not_dropped():
    ctx = execctx.build({"setup.py": b"setup(entry_points={'console_scripts': ['foo=a:main', 'junk'], 'g': ['bad']})\n"})
    assert "foo -> a:main" in _line(ctx, "commands") and "<computed>" in _line(ctx, "commands")
    assert "g: <computed>" in _line(ctx, "plugins")


def test_a_non_string_group_key_is_not_dropped():
    ctx = execctx.build({"setup.py": b"setup(entry_points={5: ['a = b:c']})\n"})
    assert "<computed>" in _line(ctx, "plugins") and "<computed>" in _line(ctx, "commands")


# ---- fix round 3: setup.py is arbitrary code, so "none" is never bare while it exists ----

NOT_LITERAL = "none declared literally in setup.py (setup.py runs arbitrary code at build)"
_EP = "entry_points={'pytest11': ['p = evil:hook']}"
_DECOY = "if False:\n    setuptools.setup(name='x')\n"


def _plugins(src: str) -> str:
    return _line(execctx.build({"setup.py": src.encode()}), "plugins").split("run): ", 1)[1]


def test_with_setup_py_an_undeclared_field_is_never_a_bare_none():
    ctx = execctx.build({"setup.py": b"from setuptools import setup\nsetup(name='a')\n"})
    for field in ("cmdclass", "setup_requires", "py-modules"):
        assert f"{field}={NOT_LITERAL}" in ctx, field
    assert _line(ctx, "commands").endswith(f": {NOT_LITERAL}") and _line(ctx, "plugins").endswith(f": {NOT_LITERAL}")


def test_without_setup_py_a_bare_none_is_still_allowed():
    ctx = execctx.build({"pyproject.toml": b"[project]\nname = 'a'\n"})
    assert "cmdclass=none" in ctx and "setup_requires=none" in ctx and _line(ctx, "commands").endswith(": none")
    assert "declared literally" not in ctx


@pytest.mark.parametrize("src", [
    f"import setuptools\nexec(\"setuptools.setup(name='x', {_EP})\")\n" + _DECOY,       # exec: covered by wording
    f"import setuptools\neval(\"setuptools.setup(name='x', {_EP})\")\n" + _DECOY,
    "import _build_helpers\nfrom setuptools import setup\nsetup(name='x')\n",
    "from setuptools import setup\nfrom _b import Dist\nsetup(name='x', distclass=Dist)\n",
])
def test_a_hidden_setup_reads_not_declared_literally_never_none(src):
    assert _plugins(src) in (NOT_LITERAL, "entry points=<computed>")


@pytest.mark.parametrize("src", [
    f"import setuptools\nrun = setuptools.setup\nrun({_EP})\n" + _DECOY,                  # (a) attribute alias
    f"import distutils.core\nrun = distutils.core.setup\nrun({_EP})\nif False:\n    distutils.core.setup(name='x')\n",
    f"import functools, setuptools\np = functools.partial(setuptools.setup, {_EP})\np()\n" + _DECOY,
    f"import sys, setuptools\nm = sys.modules['setuptools']\nf = m.setup\nf({_EP})\n" + _DECOY,
    f"import setuptools\n_o = setuptools.setup\nsetuptools.setup = lambda **k: _o({_EP}, **k)\nsetuptools.setup(name='x')\n",
    "import setuptools\ndel setuptools.setup\nsetuptools.setup(name='x')\n",                # (b) store / del
    f"import setuptools\ndef w(**k):\n    return 1\nsetattr(setuptools, 'setup', w)\nsetuptools.setup(name='x')\n",
    "from _build_helpers import *\nsetup(name='x')\n",                                      # (c) foreign star import
    "from distutils import *\nsetup(name='x')\n",
])
def test_cheap_indirect_routes_make_every_keyword_computed(src):
    assert _all_computed(execctx.build({"setup.py": src.encode()})), src


@pytest.mark.parametrize("src", [
    f"from setuptools import *\nsetup({_EP})\n",
    f"from setuptools.command import *\nfrom setuptools import setup\nsetup({_EP})\n",
    f"from distutils.core import *\nsetup({_EP})\n",
    f"try:\n    from setuptools import setup\nexcept ImportError:\n    from distutils.core import setup\nsetup({_EP})\n",
    f"from setuptools import setup\nif __name__ == '__main__':\n    setup({_EP})\n",
    f"from setuptools import setup\nns = {{}}\nexec(open('pkg/_v.py').read(), ns)\nsetup(version=ns['v'], {_EP})\n",
    f"import setuptools as st\nst.setup({_EP})\n",
])
def test_common_legitimate_setup_py_forms_stay_literal(src):
    assert "pytest11: p -> evil:hook" in _plugins(src), src


# ---- fix round 3: oversized build files and malformed / dynamic pyproject tables ----

def test_an_oversized_setup_py_is_unknown_not_absent():
    ctx = execctx.build({"pkg/__init__.py": b""}, too_large=["setup.py", "pkg/huge.py"])
    assert "setup.py=unknown (too large to scan)" in ctx and "setup.py: unknown (too large to scan)" in ctx.split("\n")
    assert "absent" not in ctx and "huge.py" not in ctx
    u = "unknown (setup.py too large)"
    assert _line(ctx, "plugins").endswith(u) and _line(ctx, "commands").endswith(u)
    assert f"cmdclass={u}" in ctx and f"setup_requires={u}" in ctx and f"py-modules={u}" in ctx


def test_an_oversized_pyproject_makes_the_backend_unknown():
    ctx = execctx.build({"setup.py": b"from setuptools import setup\nsetup()\n"}, too_large=["pyproject.toml"])
    assert "backend=unknown" in ctx and "backend-path=unknown (pyproject.toml too large)" in ctx
    assert "pyproject.toml: unknown (too large to scan)" in ctx.split("\n")


@pytest.mark.parametrize("pp", [b"project = 5\n", b"tool = {setuptools = 5}\n", b"[tool]\nsetuptools = 5\n"])
def test_a_wrong_typed_pyproject_table_is_unknown(pp):
    ctx = execctx.build({"pyproject.toml": pp})
    assert "unknown (pyproject.toml malformed)" in ctx
    if pp.startswith(b"project"):
        assert _line(ctx, "plugins").endswith("unknown (pyproject.toml malformed)")
    else:
        assert "cmdclass=unknown (pyproject.toml malformed)" in ctx


def test_dynamic_entry_points_are_unknown():
    ctx = execctx.build({"pyproject.toml": b"[project]\nname = 'a'\ndynamic = ['entry-points', 'version']\n"})
    assert _line(ctx, "plugins").endswith("unknown (pyproject.toml marks them dynamic)")
    assert _line(ctx, "commands").endswith("unknown (pyproject.toml marks them dynamic)")


# ---- fix round 4: poetry / flit entry points, other backends ----

POETRY = b"""\
[build-system]
requires = ["poetry-core"]
build-backend = "poetry.core.masonry.api"
[tool.poetry]
name = "a"
[tool.poetry.scripts]
foo = "a:main"
[tool.poetry.plugins.pytest11]
p = "evil:hook"
[tool.poetry.plugins.console_scripts]
bar = "a:bar"
"""

FLIT = b"""\
[build-system]
requires = ["flit_core"]
build-backend = "flit_core.buildapi"
[tool.flit.metadata]
module = "a"
[tool.flit.scripts]
foo = "a:main"
[tool.flit.entrypoints.pytest11]
p = "evil:hook"
"""


def test_poetry_scripts_and_plugins_are_read():
    ctx = execctx.build({"pyproject.toml": POETRY})
    assert _line(ctx, "commands").endswith(": foo -> a:main, bar -> a:bar")      # console_scripts plugin = command
    assert _line(ctx, "plugins").endswith(": pytest11: p -> evil:hook")


def test_flit_scripts_and_entrypoints_are_read():
    ctx = execctx.build({"pyproject.toml": FLIT})
    assert _line(ctx, "commands").endswith(": foo -> a:main")
    assert _line(ctx, "plugins").endswith(": pytest11: p -> evil:hook")


@pytest.mark.parametrize("pp", [
    b"[tool.poetry]\nscripts = 5\n",
    b"[tool.poetry]\nplugins = 5\n",
    b"[tool.poetry.plugins]\npytest11 = 5\n",
    b"[tool.poetry.scripts]\nfoo = {reference = 'a:main', type = 'console'}\n",
    b"[tool.poetry.scripts]\nfoo = 5\n",
    b"[tool.flit]\nscripts = ['x']\n",
    b"[tool.flit]\nentrypoints = 'x'\n",
    b"[tool.flit.entrypoints]\npytest11 = [1]\n",
])
def test_wrong_typed_poetry_or_flit_entry_points_are_computed(pp):
    ctx = execctx.build({"pyproject.toml": pp})
    assert "<computed>" in _line(ctx, "commands") + _line(ctx, "plugins"), pp


@pytest.mark.parametrize("pp", [b"tool = {poetry = 5}\n", b"tool = {flit = 'x'}\n"])
def test_a_wrong_typed_poetry_or_flit_table_is_malformed(pp):
    ctx = execctx.build({"pyproject.toml": pp})
    assert _line(ctx, "plugins").endswith("unknown (pyproject.toml malformed)")


def test_an_unparsed_backend_says_it_may_declare_its_own_entry_points():
    ctx = execctx.build({"pyproject.toml": b"[build-system]\nbuild-backend = 'hatchling.build'\n[project]\nname = 'a'\n"})
    u = "none in [project] (hatchling.build may declare its own)"
    assert _line(ctx, "commands").endswith(f": {u}") and _line(ctx, "plugins").endswith(f": {u}")
    ctx = execctx.build({"pyproject.toml": b"[build-system]\nbuild-backend = 'hatchling.build'\n",
                         "setup.py": b"from setuptools import setup\nsetup()\n"})
    assert _line(ctx, "plugins").endswith(f": {u}; {NOT_LITERAL}")


@pytest.mark.parametrize("backend", ["setuptools.build_meta", "poetry.core.masonry.api", "flit_core.buildapi"])
def test_parsed_backends_keep_the_plain_none(backend):
    ctx = execctx.build({"pyproject.toml": f"[build-system]\nbuild-backend = '{backend}'\n".encode()})
    assert _line(ctx, "plugins").endswith(": none"), backend


# ---- fix round 4: setup.cfg file: / attr: directives ----

def _cfg(options: str) -> str:
    return execctx.build({"setup.cfg": f"[metadata]\nname = a\n[options]\n{options}\n".encode()})


def test_a_setup_cfg_entry_points_file_directive_is_unknown():
    ctx = _cfg("entry_points = file: eps.cfg")
    u = "unknown (setup.cfg reads entry points from a file)"
    assert _line(ctx, "commands").endswith(f": {u}") and _line(ctx, "plugins").endswith(f": {u}")


def test_a_setup_cfg_inline_entry_points_string_is_read():
    ctx = _cfg("entry_points =\n    [pytest11]\n    p = evil:hook")
    assert _line(ctx, "plugins").endswith(": pytest11: p -> evil:hook")


@pytest.mark.parametrize("key, field, what", [
    ("packages", "packages", "packages"),
    ("py_modules", "py-modules", "py-modules"),
    ("setup_requires", "setup_requires", "setup_requires"),
])
@pytest.mark.parametrize("directive, src", [("file: x.txt", "a file"), ("attr: a.b", "a Python attribute")])
def test_setup_cfg_directives_on_declaring_keys_are_unknown(key, field, what, directive, src):
    ctx = _cfg(f"{key} = {directive}")
    assert f"{field}=unknown (setup.cfg reads {what} from {src})" in ctx, ctx


# ---- fix round 4: oversized non-build sources ----

def test_an_oversized_pth_is_unknown_startup():
    ctx = execctx.build({"a.pth": b"import os\n"}, too_large=["evil.pth", "pkg/huge.py"])
    assert _line(ctx, "startup").endswith(": a.pth: 1 import line, unknown (evil.pth too large to scan)")
    assert "huge.py" not in ctx


def test_an_oversized_egg_info_entry_points_txt_is_unknown():
    ctx = execctx.build({"pyproject.toml": b"[project]\nname = 'a'\n"}, too_large=["a.egg-info/entry_points.txt"])
    u = "unknown (a.egg-info/entry_points.txt too large)"
    assert _line(ctx, "commands").endswith(f": {u}") and _line(ctx, "plugins").endswith(f": {u}")
    assert "cmdclass=none" in ctx                       # entry_points.txt declares only entry points


# ---- fix round 4: no bare "none" left while setup.py exists ----

def test_with_setup_py_auto_discovery_and_startup_are_never_a_bare_none():
    ctx = execctx.build({"setup.py": b"from setuptools import setup\nsetup(name='a')\n"})
    assert f"packages=auto-discovered: {NOT_LITERAL}" in ctx
    assert _line(ctx, "startup").endswith(f": {NOT_LITERAL}")


@pytest.mark.parametrize("src, field", [
    ("import setuptools\nsetuptools.setup(packages=[])\n", "packages"),
    ("import setuptools\nexec('...')\nsetuptools.setup(py_modules=[])\n", "py-modules"),
])
def test_with_setup_py_a_literal_empty_list_is_never_a_bare_none(src, field):
    assert f"{field}={NOT_LITERAL}" in execctx.build({"setup.py": src.encode()})


def test_without_setup_py_empty_discovery_and_startup_stay_none():
    ctx = execctx.build({"pyproject.toml": b"[project]\nname = 'a'\n"})
    assert "packages=auto-discovered: none;" in ctx and _line(ctx, "startup").endswith(": none")


# ---- fix round 5: top-level metadata paths never raise ----

@pytest.mark.parametrize("files, too_large", [
    ({"entry_points.txt": b"[pytest11]\np = e:h\n"}, ()),
    ({"top_level.txt": b"a\n"}, ()),
    ({"pyproject.toml": b"[project]\nname = 'a'\n"}, ("entry_points.txt",)),
    ({}, ("top_level.txt",)),
    ({"entry_points.txt": b"x", "top_level.txt": b"a"}, ("entry_points.txt", "top_level.txt", "a.pth", "x")),
])
def test_top_level_metadata_paths_never_raise(files, too_large):
    assert isinstance(execctx.build(files, too_large), str)


# ---- fix round 5: unparsed or in-tree backends may generate their own files ----

def test_an_unparsed_backend_without_setup_py_qualifies_startup_and_discovery():
    ctx = execctx.build({"pyproject.toml": b"[build-system]\nbuild-backend = 'hatchling.build'\n[project]\nname = 'a'\n"})
    g = "none in scanned files (hatchling.build may generate its own)"
    assert _line(ctx, "startup").endswith(f": {g}")
    assert f"packages=auto-discovered: {g};" in ctx and f"py-modules={g};" in ctx


@pytest.mark.parametrize("backend", ["setuptools.build_meta", "poetry.core.masonry.api", "flit_core.buildapi"])
def test_a_backend_path_makes_even_a_parsed_backend_name_in_tree(backend):
    ctx = execctx.build({"pyproject.toml": f"[build-system]\nbuild-backend = '{backend}'\nbackend-path = ['.']\n".encode()})
    d = f"none in [project] (in-tree backend {backend} may declare its own)"
    g = f"none in scanned files (in-tree backend {backend} may generate its own)"
    assert _line(ctx, "commands").endswith(f": {d}") and _line(ctx, "plugins").endswith(f": {d}")
    assert _line(ctx, "startup").endswith(f": {g}")


def test_an_empty_backend_path_is_not_in_tree():
    ctx = execctx.build({"pyproject.toml": b"[build-system]\nbuild-backend = 'setuptools.build_meta'\nbackend-path = []\n"})
    assert _line(ctx, "plugins").endswith(": none") and _line(ctx, "startup").endswith(": none")


# ---- fix round 5: flit's entry-points-file ----

_FLIT_OLD = "[build-system]\nbuild-backend = 'flit_core.buildapi'\n[tool.flit.metadata]\nmodule = 'a'\n"


def test_flit_reads_its_default_top_level_entry_points_txt():
    ctx = execctx.build({"pyproject.toml": _FLIT_OLD.encode(), "entry_points.txt": b"[pytest11]\np = e:h\n"})
    assert _line(ctx, "plugins").endswith(": pytest11: p -> e:h")


def test_flit_reads_a_named_entry_points_file():
    ctx = execctx.build({"pyproject.toml": (_FLIT_OLD + "entry-points-file = 'eps/ep.txt'\n").encode(),
                         "eps/ep.txt": b"[console_scripts]\nfoo = a:main\n"})
    assert _line(ctx, "commands").endswith(": foo -> a:main")


@pytest.mark.parametrize("extra, files, too_large, expect", [
    ("entry-points-file = 'eps.cfg'\n", {}, (), "unknown (flit entry-points-file eps.cfg not in scanned files)"),
    ("entry-points-file = 5\n", {}, (), "unknown (flit entry-points-file <computed>)"),
    ("", {}, ("entry_points.txt",), "unknown (entry_points.txt too large)"),
    ("", {"entry_points.txt": b"[x"}, (), "unknown (entry_points.txt unparseable)"),
])
def test_an_unread_flit_entry_points_file_is_unknown(extra, files, too_large, expect):
    ctx = execctx.build({"pyproject.toml": (_FLIT_OLD + extra).encode(), **files}, too_large)
    assert _line(ctx, "plugins").endswith(f": {expect}") and _line(ctx, "commands").endswith(f": {expect}")


def test_a_top_level_entry_points_txt_is_not_flit_s_under_another_backend():
    ctx = execctx.build({"pyproject.toml": b"[project]\nname = 'a'\n", "entry_points.txt": b"[pytest11]\np = e:h\n"})
    assert "p -> e:h" not in ctx


def test_an_unknown_backend_qualifies_like_an_unparsed_one():
    ctx = execctx.build({"pyproject.toml": b"[build-system]\nbuild-backend = 5\n"})
    assert "backend=unknown" in ctx
    assert _line(ctx, "plugins").endswith(": none in [project] (unknown backend may declare its own)")
    assert _line(ctx, "startup").endswith(": none in scanned files (unknown backend may generate its own)")
