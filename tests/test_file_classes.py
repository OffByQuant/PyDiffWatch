"""Spec F §3.1: every changed file gets the class of when it runs. Synthetic sdists only; nothing is executed."""
import pytest

from pydiffwatch import execctx


def _c(files, paths=None):
    files = {p: (b if isinstance(b, bytes) else b.encode()) for p, b in files.items()}
    return execctx.classify(files, paths if paths is not None else list(files))


def test_the_class_order_is_the_run_order():
    assert execctx.CLASSES == ("build", "startup", "import", "user-command", "plugin-host", "runtime-call",
                               "not-shipped", "data", "inert")
    assert execctx.RUNNABLE == execctx.CLASSES[:6]


@pytest.mark.parametrize("path, cls", [
    ("setup.py", "build"), ("x.pth", "startup"), ("pkg/sitecustomize.py", "startup"),
    ("pkg/__init__.py", "import"), ("src/pkg/__init__.py", "import"), ("mod.py", "import"),
    ("src/mod.py", "import"), ("pkg/core.py", "runtime-call"), ("pkg/fast.pyx", "runtime-call"),
    ("tests/test_x.py", "not-shipped"), ("docs/conf.py", "not-shipped"), ("tools/gen.py", "not-shipped"),
    ("pkg/conftest.py", "not-shipped"), ("pkg/py.typed", "data"), ("pkg/core.pyi", "inert"),
    ("PKG-INFO", "inert"), ("README.md", "inert"), ("pyproject.toml", "data"), ("setup.cfg", "data"),
    ("pkg/data.json", "data"), ("conftest.py", "not-shipped"),
])
def test_classify_path(path, cls):
    assert execctx.classify_path(path) == cls


def test_setup_py_imports_are_build_even_under_tests():
    got = _c({"setup.py": "from tests.helper import run\nimport _build_ext\nsetup()\n",
              "tests/helper.py": "x = 1\n", "_build_ext.py": "y = 1\n", "tests/test_a.py": "z = 1\n"})
    assert (got["tests/helper.py"], got["_build_ext.py"], got["tests/test_a.py"]) == ("build", "build",
                                                                                     "not-shipped")


def test_backend_path_and_build_hooks_are_build():
    pp = ('[build-system]\nrequires = []\nbuild-backend = "backend"\nbackend-path = ["_custom"]\n'
          '[tool.hatch.build.hooks.custom]\npath = "scripts/hatch_hook.py"\n'
          '[tool.poetry]\nbuild = "build_script.py"\n'
          '[tool.setuptools.cmdclass]\nbuild_py = "tools.cmds.BuildPy"\n')
    got = _c({"pyproject.toml": pp, "_custom/backend.py": "", "scripts/hatch_hook.py": "",
              "build_script.py": "", "tools/cmds.py": "", "pdm_build.py": "", "scripts/other.py": ""})
    assert {p: got[p] for p in ("_custom/backend.py", "scripts/hatch_hook.py", "build_script.py",
                                "tools/cmds.py", "pdm_build.py")} == dict.fromkeys(
        ("_custom/backend.py", "scripts/hatch_hook.py", "build_script.py", "tools/cmds.py", "pdm_build.py"), "build")
    assert got["scripts/other.py"] == "not-shipped"


def test_hatch_default_hook_path():
    got = _c({"pyproject.toml": "[tool.hatch.build.targets.wheel.hooks.custom]\n", "hatch_build.py": ""})
    assert got["hatch_build.py"] == "build"


def test_entry_points_and_scripts():
    pp = ('[project]\nname = "p"\n[project.scripts]\np = "pkg.cli:main"\n'
          '[project.entry-points.pytest11]\np = "pkg.plugin"\n')
    got = _c({"pyproject.toml": pp, "pkg/__init__.py": "", "pkg/cli.py": "", "pkg/plugin.py": "",
              "pkg/other.py": ""})
    assert (got["pkg/cli.py"], got["pkg/plugin.py"], got["pkg/other.py"], got["pkg/__init__.py"]) == (
        "user-command", "plugin-host", "runtime-call", "import")


def test_setup_py_scripts_and_entry_points():
    sp = ("from setuptools import setup\nsetup(name='p', scripts=['bin/tool'], "
          "entry_points={'console_scripts': ['t=pkg.cmd:main'], 'myhost.plugins': ['x=pkg.plug']})\n")
    got = _c({"setup.py": sp, "bin/tool": "#!/bin/sh\n", "pkg/__init__.py": "", "pkg/cmd.py": "",
              "pkg/plug.py": ""})
    assert (got["bin/tool"], got["pkg/cmd.py"], got["pkg/plug.py"]) == ("user-command", "user-command",
                                                                        "plugin-host")


def test_modules_an_init_imports_are_import():
    got = _c({"pkg/__init__.py": "from . import _boot\nfrom pkg.sub import thing\n", "pkg/_boot.py": "",
              "pkg/sub.py": "", "pkg/idle.py": ""})
    assert (got["pkg/_boot.py"], got["pkg/sub.py"], got["pkg/idle.py"]) == ("import", "import", "runtime-call")


@pytest.mark.parametrize("files, path", [
    ({"nspkg/mod.py": "exec(x)\n"}, "nspkg/mod.py"),                                    # PEP 420 namespace
    ({"setup.cfg": "[options]\npackage_dir =\n  = lib\n", "lib/mypkg/_boot.py": "exec(x)\n"}, "lib/mypkg/_boot.py"),
    ({"tools/__init__.py": "", "tools/run.py": "exec(x)\n"}, "tools/run.py"),            # a package named tools
])
def test_code_no_row_matches_is_never_data(files, path):
    # review C1: real code in an unusual layout is runtime-call (or not-shipped), never data
    assert _c(files)[path] in ("runtime-call", "not-shipped", "import")
    assert _c(files)[path] != "data"


def test_declared_package_dir_packages_are_import():
    sp = "from setuptools import setup\nsetup(name='p', packages=['mypkg'], package_dir={'': 'lib'})\n"
    got = _c({"setup.py": sp, "lib/mypkg/__init__.py": "", "lib/mypkg/_boot.py": ""})
    assert got["lib/mypkg/__init__.py"] == "import"


def test_only_the_asked_paths_are_classified_and_hostile_metadata_never_raises():
    files = {"pyproject.toml": b"\x00[[[", "setup.cfg": b"[options\n", "setup.py": b"def (:\n",
             "pkg/__init__.py": b"from .... import x\n"}
    assert execctx.classify(files, ["pkg/__init__.py"]) == {"pkg/__init__.py": "import"}


def test_module_file_and_local_imports():
    files = {"a/b.py": b"", "src/c/__init__.py": b"", "d.pyx": b""}
    assert (execctx.module_file("a.b", files), execctx.module_file("c", files), execctx.module_file("d", files),
            execctx.module_file("x", files), execctx.module_file("../etc", files)) == (
        "a/b.py", "src/c/__init__.py", "d.pyx", None, None)
    assert execctx.local_imports("a/__init__.py", b"from .b import f\nimport c\nimport os\n", files) == {
        "a/b.py", "src/c/__init__.py"}
