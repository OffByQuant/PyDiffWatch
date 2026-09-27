"""Where package bytes are parsed (parse-sandbox spec §3.1). C1: only the in-process backend ("off"). The
parent keeps the network, the database, the reviewer and the notifier; `compute` is everything that reads
author bytes (unpack, diff, triage), and is what the C2 worker will run in a sandbox.
`analyze` then applies what only the parent may decide: the signal line from its own data, and the dep and
maintainer rule results from its own metadata (npm #31), merged in ruleset order."""
import dataclasses
import json
import math
import os
import sys
from pathlib import Path

from . import differ, engine, fetcher
from .config import Config
from .models import Diff, Download, FileDiff, FiredRule, Hunk, TriageResult
from .rules import Rule

_backend = "off"
_PARENT_RULES = {"maintainer", "dep"}
_PATH_FIELDS = ("db_path", "cache_dir", "lock_path", "rules_dir")
_ROOT = Path(__file__).resolve().parent.parent      # the directory pydiffwatch is imported from


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


# ---- parent -> worker: one JSON line, then the raw sdists ----
def _home() -> str:
    return os.path.realpath(os.path.expanduser("~"))


def _import_paths() -> list[str]:
    """Where the worker imports from: the parent's own import path (so it runs exactly the parent's code), real
    paths only, minus HOME and its ancestors, which would open up the whole home directory."""
    home = _home()
    out = []
    for p in [str(_ROOT)] + sys.path:
        rp = os.path.realpath(p or os.getcwd())
        if os.path.isdir(rp) and not (home == rp or home.startswith(rp.rstrip("/") + "/")) and rp not in out:
            out.append(rp)
    return out


def _cfg_to_dict(cfg) -> dict:
    """Every Config field but the reviewer's; the four paths resolved here, since the worker must never resolve a
    relative path against a directory of its own."""
    d = {f.name: getattr(cfg, f.name) for f in dataclasses.fields(cfg) if f.name != "reviewer"}
    for k in _PATH_FIELDS:
        d[k] = str(Path(d[k]).resolve())
    return d


def _cfg_from_dict(d: dict) -> Config:
    return Config(**{k: (Path(v) if k in _PATH_FIELDS else v) for k, v in d.items()})


def _encode_input(cfg, dl: Download, ruleset) -> bytes:
    """The request: one JSON line (sort_keys), then new_blob, then prior_blob. The parent's loaded rules travel in
    it (npm #36: the worker never reads rules_dir). No owners, added_dep_findings or requires_dist_change: those
    facts are the parent's (spec decision 5)."""
    head = {"cfg": _cfg_to_dict(cfg), "sys_path": _import_paths(),
            "rules": [dataclasses.asdict(r) for r in ruleset],
            "dl": {"package": dl.package, "version": dl.version, "prior_version": dl.prior_version,
                   "is_new_package": dl.is_new_package, "maintainer_metadata": dl.maintainer_metadata,
                   "description": dl.description, "prior_error": dl.prior_error, "new_len": len(dl.new_blob),
                   "prior_len": None if dl.prior_blob is None else len(dl.prior_blob)}}
    return json.dumps(head, sort_keys=True).encode() + b"\n" + dl.new_blob + (dl.prior_blob or b"")


def _decode_input(head: dict, stream):
    """The worker's side of _encode_input: (Config, Download, ruleset). The Download carries no parent-owned
    facts: added_dep_findings=[] and requires_dist_change=None."""
    m = head["dl"]
    new = stream.read(m["new_len"])
    prior = stream.read(m["prior_len"]) if m["prior_len"] is not None else None
    if len(new) != m["new_len"] or (prior is not None and len(prior) != m["prior_len"]):
        raise ValueError("the request ended before its sdists did")
    dl = Download(m["package"], m["version"], m["prior_version"], m["is_new_package"], new, prior,
                  m["prior_error"], m["maintainer_metadata"], [], None, m["description"])
    return _cfg_from_dict(head["cfg"]), dl, [Rule(**r) for r in head["rules"]]


# ---- worker -> parent: JSON, checked field by field ----
def _encode_output(art, d: Diff, tr: TriageResult) -> bytes:
    """The reply: one JSON line (sort_keys). No signals, no added_dep_findings and no score: the parent's."""
    return json.dumps({
        "diff": {"package": d.package, "version": d.version, "is_first_release": d.is_first_release,
                 "changed": [{"path": f.path, "change_kind": f.change_kind, "new_text": f.new_text,
                              "hunks": [{"old_range": list(h.old_range), "new_range": list(h.new_range),
                                         "added": h.added, "removed": h.removed} for h in f.hunks]}
                             for f in d.changed],
                 "added_binaries": d.added_binaries, "description": d.description,
                 "exec_context": d.exec_context, "baseline_unavailable": d.baseline_unavailable,
                 "surface_omitted": d.surface_omitted},
        "triage": {"fired_rules": [{"rule": r.rule, "weight": r.weight, "file": r.file, "lines": list(r.lines)}
                                   for r in tr.fired_rules]},
        "prior_error": art.prior_error}, sort_keys=True).encode()


def _check(ok: bool, what: str):
    if not ok:
        raise SandboxError(f"sandbox sent back a malformed {what}")


def _str(v, what, optional=False):
    _check(isinstance(v, str) or (optional and v is None), what)
    return v


def _list(v, what):
    _check(isinstance(v, list), what)
    return v


def _strs(v, what):
    _check(isinstance(v, list) and all(isinstance(x, str) for x in v), what)
    return v


def _pair(v, what):
    _check(isinstance(v, list) and len(v) == 2 and all(type(x) is int for x in v), what)
    return tuple(v)


def _dict(v, what):
    _check(isinstance(v, dict) and all(isinstance(k, str) for k in v), what)
    return v


def _decode_output(raw: bytes, cfg, dl: Download, ruleset):
    """Check the worker's reply field by field (spec §3.2 "Validation") and build the parent's own Diff and
    FiredRules from it. Returns (Diff, TriageResult, prior_error): the Diff has no signals and no
    added_dep_findings, and the score is recomputed here with max_total (analyze then re-merges the parent's dep
    and maintainer results). Keys the parent does not know are ignored. Raises fetcher.RefusedToExtract for a
    refusal inside the box, SandboxError for anything else."""
    try:
        out = json.loads(raw)
    except (ValueError, UnicodeDecodeError, RecursionError) as e:
        raise SandboxError(f"sandbox sent back something that is not JSON: {e}") from e
    _dict(out, "reply")
    if "error" in out:
        if out.get("error_type") == "RefusedToExtract":
            raise fetcher.RefusedToExtract(_str(out["error"], "refusal"))
        raise SandboxError(f"sandbox worker failed: {str(out['error'])[:500]}")
    try:
        dd = _dict(out["diff"], "diff")
        _check(dd["package"] == dl.package and dd["version"] == dl.version, "diff (wrong release)")
        _check(type(dd["is_first_release"]) is bool, "diff")
        changed = []
        for f in _list(dd["changed"], "file list"):
            _dict(f, "file diff")
            _check(f["change_kind"] in ("added", "removed", "modified"), "change kind")
            hunks = []
            for h in _list(f["hunks"], "hunk list"):
                _dict(h, "hunk")
                hunks.append(Hunk(_pair(h["old_range"], "hunk range"), _pair(h["new_range"], "hunk range"),
                                  _strs(h["added"], "hunk"), _strs(h["removed"], "hunk")))
            changed.append(FileDiff(_str(f["path"], "path"), f["change_kind"], hunks,
                                    _str(f["new_text"], "file text", optional=True)))
        bins = _list(dd["added_binaries"], "binary list")
        _check(all(isinstance(b, dict) and all(isinstance(k, str) and (v is None or type(v) in (str, int))
                                               for k, v in b.items()) for b in bins), "binary list")
        omitted = dd["surface_omitted"]
        _check(omitted is None or type(omitted) is int, "surface_omitted")
        d = Diff(dd["package"], dd["version"], dd["is_first_release"], changed, bins, [],
                 _str(dd["description"], "description"), _str(dd["exec_context"], "exec context"),
                 _str(dd["baseline_unavailable"], "baseline"), omitted, "")
        prior_error = _str(out["prior_error"], "prior_error", optional=True)
        known = {r.id for r in ruleset}
        fired = []
        for r in _list(_dict(out["triage"], "triage")["fired_rules"], "fired rules"):
            _dict(r, "fired rule")
            _check(r["rule"] in known, "rule id")
            w = r["weight"]
            _check(type(w) in (int, float) and math.isfinite(w) and w >= 0, "weight")
            fired.append(FiredRule(r["rule"], float(w), _str(r["file"], "rule file"),
                                   _pair(r["lines"], "rule lines")))
    except (KeyError, TypeError, AttributeError, OverflowError) as e:
        raise SandboxError(f"sandbox sent back a malformed reply: {e!r}") from e
    score = engine.score(fired, ruleset)
    return d, TriageResult(score, fired, score >= cfg.threshold_t), prior_error


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
