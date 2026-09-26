"""Where package bytes are parsed (parse-sandbox spec §3.1). C1: only the in-process backend ("off"). The
parent keeps the network, the database, the reviewer and the notifier; `compute` is everything that reads
author bytes (unpack, diff, triage), and is what the C2 worker will run in a sandbox.
`analyze` then applies what only the parent may decide: the signal line from its own data, and the dep and
maintainer rule results from its own metadata (npm #31), merged in ruleset order."""
import dataclasses

from . import differ, engine, fetcher
from .models import Diff, TriageResult

_backend = "off"
_PARENT_RULES = {"maintainer", "dep"}


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


def analyze(cfg, dl, owners, ruleset, backend=None):
    """Scan one downloaded release. Returns (Diff, TriageResult, prior_error). Raises fetcher.RefusedToExtract
    when the new sdist is refused; SandboxError for a backend it does not know."""
    backend = backend or _backend
    if backend != "off":
        raise SandboxError(f"unknown sandbox {backend!r}")
    art, d, tr = compute(cfg, dl, ruleset)
    d = dataclasses.replace(d, added_dep_findings=list(dl.added_dep_findings),
                            signals=differ.render_signals(dl.requires_dist_change, dl.added_dep_findings,
                                                          d.added_binaries, owners))
    return d, _with_parent_rules(cfg, dl, d, tr, owners, ruleset), art.prior_error
