"""execctx: how a release's files run, parsed statically from its build metadata (spec A3).

tomllib / configparser / ast / email.parser only: nothing is imported or executed. One parser helper for every
author-written structured file (npm #25 parity): it accepts a BOM, maps a non-mapping to {}, and never raises;
a file that does not parse renders as `<file>: unparseable`."""
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


# ---- never raise: malformed input renders as `<file>: unparseable` ----

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
    assert f"{name}: unparseable" in ctx.split("\n")


def test_deep_but_valid_ini_is_just_text():
    assert "setup.cfg: unparseable" not in execctx.build({"setup.cfg": _DEEP_INI})


def test_deeply_nested_setup_literals_are_computed_not_a_crash():
    nested = b"setup(packages=" + b"[" * 150 + b"'a'" + b"]" * 150 + b")\n"
    ctx = execctx.build({"setup.py": nested})
    assert "setup.py: unparseable" not in ctx and "packages=<computed>" in ctx


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


def test_scripts_of_the_wrong_type_render_as_none():
    ctx = execctx.build({"pyproject.toml": b"[project]\nscripts = 5\n"})
    assert "commands (console_scripts/gui_scripts; run only when the user types them): none" in ctx.split("\n")
