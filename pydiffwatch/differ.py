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


_NEAR = "its name is one or two edits away from "     # nearest_corpus uses max_dist=2


def _dep_line(f) -> str:
    """One dependency finding as neutral facts (PR E): the reason's evidence, never the word "typosquat"."""
    name, reason, target = _esc(f.get("name")), f.get("reason"), f.get("target")
    near = _NEAR + (f"the popular package {_esc(target)}" if target else "a popular package")
    if reason == "typosquat":
        if "releases" not in f:
            return f"dependency {name}: {near}; not looked up"
        owner = "a different PyPI owner from this package" if f.get("owner") == "different" else "PyPI owner unknown"
        line = (f"dependency {name}: {near}; first published {_esc(f.get('first_upload') or 'unknown')}, "
                f"{int(f.get('releases') or 0)} release(s); {owner}")
        if f.get("pypi_org"):
            line += f"; published under the PyPI organisation {_esc(f['pypi_org'])}"
        if f.get("same_author_email"):
            line += "; its metadata names the same author email as this package (author-declared)"
        if f.get("same_org"):
            line += "; its project URLs name the same code-host organisation as this package's (author-declared)"
        if f.get("same_author_as_target") and target:
            line += f"; its metadata names the same author as {_esc(target)} (author-declared)"
        return line
    if reason == "nonexistent" and target:
        return f"dependency {name}: not on PyPI (dependency confusion); {near}"
    if reason == "brand-new" and f.get("same_owner"):
        return f"dependency {name}: brand-new on PyPI; the same PyPI owner as this package"
    return f"dependency {name}: {_DEP_REASONS.get(reason) or _esc(reason)}"


def render_signals(requires_dist_change, added_dep_findings, added_binaries, maintainer_context) -> str:
    """The dependency / binary / ownership signals triage scored, one line each, for the reviewer (spec B2).
    Rendered by the parent from its own data (parse-sandbox spec decision 5). Every author-written value (names,
    specifiers, paths, owners) is escaped to one line here."""
    out = []
    for key in ("added", "removed"):
        if items := (requires_dist_change or {}).get(key):
            out.append(f"requires-dist {key}: {_list(items)}")
    deps = [_dep_line(f) for f in added_dep_findings]
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
                "", requires_python=a.requires_python)
