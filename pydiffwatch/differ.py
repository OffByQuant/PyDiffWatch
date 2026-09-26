import difflib
from . import execctx, facts
from .models import ArtifactSet, Diff, FileDiff, Hunk

def _lines(b: bytes) -> list[str]:
    return b.decode("utf-8", errors="replace").splitlines()

def _description(summary) -> str:
    return " ".join(summary.split())[:500] if isinstance(summary, str) else ""   # one line: it must not pose as a hunk


_MAX_ITEMS = 20


def _esc(s) -> str:
    """An author-written value on one line (control and line-separator characters escaped), clipped."""
    s = "".join(c if c.isprintable() else repr(c)[1:-1] for c in str(s))
    return s if len(s) <= 200 else s[:200] + "…"


def _capped(label: str, lines: list[str]) -> list[str]:
    more = len(lines) - _MAX_ITEMS
    return lines[:_MAX_ITEMS] + ([f"{label}: … (+{more} more)"] if more > 0 else [])


def _list(items) -> str:
    items = [_esc(x) for x in items]
    more = len(items) - _MAX_ITEMS
    return ", ".join(items[:_MAX_ITEMS]) + (f", … (+{more} more)" if more > 0 else "")


_DEP_REASONS = {"nonexistent": "not on PyPI (dependency confusion)", "brand-new": "brand-new on PyPI",
                "not-screened-cap": "not screened (lookup cap reached)"}


def render_signals(requires_dist_change, added_dep_findings, added_binaries, maintainer_context) -> str:
    """The dependency / binary / ownership signals triage scored, one line each, for the reviewer (spec B2).
    Rendered by the parent from its own data (parse-sandbox spec decision 5). Every author-written value (names,
    specifiers, paths, owners) is escaped to one line here."""
    out = []
    for key in ("added", "removed"):
        if items := (requires_dist_change or {}).get(key):
            out.append(f"requires-dist {key}: {_list(items)}")
    deps = []
    for f in added_dep_findings:
        why = ((f"typosquat of {_esc(f['target'])} (a popular package)" if f.get("target") else "typosquat")
               if f.get("reason") == "typosquat" else _DEP_REASONS.get(f.get("reason")) or _esc(f.get("reason")))
        deps.append(f"dependency {_esc(f.get('name'))}: {why}")
    out += _capped("dependency", deps)
    bins = []
    # unscored oversized files last: the shared cap must never cut a scored line for one
    for b in sorted(facts._normalize_binaries(added_binaries), key=lambda b: b["reason"] == "file-too-large"):
        reason = _esc(b.get("reason") or "unknown") + (f" ({_esc(b['ext'])})" if b.get("ext") else "")
        bins.append(f"added file {_esc(b.get('path'))}: {_esc(b.get('size'))} bytes, {reason}")
    out += _capped("added file", bins)
    if change := facts.roles_change(maintainer_context):
        out.append(f"maintainer set changed: {_list(change[0])} -> {_list(change[1])}")
    return "\n".join(out)


def build_diff(a: ArtifactSet) -> Diff:
    changed: list[FileDiff] = []
    for path in sorted(set(a.new_files) | set(a.prior_files)):
        new, prior = a.new_files.get(path), a.prior_files.get(path)
        if new is not None and prior is not None and new == prior:
            continue
        nl, pl = _lines(new or b""), _lines(prior or b"")
        kind = "added" if prior is None else "removed" if new is None else "modified"
        hunks: list[Hunk] = []
        for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, pl, nl).get_opcodes():
            if tag == "equal":
                continue
            hunks.append(Hunk((i1, i2), (j1, j2), nl[j1:j2], pl[i1:i2]))
        if hunks:
            new_text = new.decode("utf-8", errors="replace") if new is not None else None
            changed.append(FileDiff(path, kind, hunks, new_text))
    return Diff(a.package, a.version, a.prior_version is None, changed,
                list(a.added_binaries), list(a.added_dep_findings), _description(a.description),
                execctx.build(a.new_files, a.too_large),
                a.prior_version if a.prior_error and a.prior_version else "", a.surface_omitted,
                "")
