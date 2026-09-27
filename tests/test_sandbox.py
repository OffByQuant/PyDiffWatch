"""C1 part of the parse sandbox (spec §3.1): analyze(backend="off") scans in-process through the same
compute + parent-rules path the C2 worker will use."""
import dataclasses, pathlib

import pytest

from pydiffwatch import engine, fetcher, rules, sandbox
from pydiffwatch.config import Config
from pydiffwatch.models import Download, FiredRule, TriageResult
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
