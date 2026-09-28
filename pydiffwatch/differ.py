import difflib
import re
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


def render_signals(requires_dist_change, added_dep_findings, added_binaries, maintainer_context,
                   publishing=None) -> str:
    """The dependency / ownership / publishing signals, one line each, for the reviewer (spec B2, F decision 6).
    Rendered by the parent from its own data (parse-sandbox spec decision 5). Every author-written value is escaped
    to one line here. Binaries are listed by render_unreadable instead (spec F Ruling F4); `added_binaries` stays in
    the signature for callers."""
    out = []
    for key in ("added", "removed"):
        if items := (requires_dist_change or {}).get(key):
            out.append(f"requires-dist {key}: {_list(items)}")
    out += _capped("dependency", [_dep_line(f) for f in added_dep_findings])
    if change := facts.roles_change(maintainer_context):
        out.append(f"maintainer set changed: {_list(change[0])} -> {_list(change[1])}")
    if isinstance(publishing, dict):
        n, d = publishing.get("releases"), publishing.get("days_since_prior")
        out.append(f"releases on PyPI: {n if type(n) is int else 'unknown'}")
        out.append("days since the previous release: "
                   + (str(d) if type(d) is int else "none (no earlier release)"))
    return "\n".join(out)


def render_unreadable(added_binaries) -> str:
    """The changed files DiffWatch could not show as text (binaries, oversized or foreign-language members), one
    line each, unscored oversized files last (spec F §3.2). Author paths escaped to one line."""
    lines = []
    for b in sorted(facts._normalize_binaries(added_binaries), key=lambda b: b["reason"] == "file-too-large"):
        reason = _esc(b.get("reason") or "unknown") + (f" ({_esc(b['ext'])})" if b.get("ext") else "")
        lines.append(f"{_esc(b.get('path'))}: {_esc(b.get('size'))} bytes, {reason}")
    return "\n".join(_capped("not readable", lines))


_MAX_HOOK_TARGETS = 20      # carried to the reviewer, which shows at most 5 whole (spec F §3.2)
_HOOK_SOURCES = ("setup.py", "pyproject.toml", "setup.cfg")
_EP_TARGET = re.compile(r"(?<![\w.])([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*:\s*[A-Za-z_]\w*")
_PY_PATH = re.compile(r"""["']((?:\./)?[\w./-]+\.py)["']""")


def _hook_targets(new_files, changed) -> list[FileDiff]:
    """Unchanged files that a changed setup.py, pyproject.toml, setup.cfg or entry_points.txt names in an ADDED
    line — an import in setup.py, an entry-point target `mod:attr`, a quoted *.py path (Ruling F6) — carried whole
    so the reviewer sees code this release newly runs (spec F §2.5). Never scored: not in Diff.changed."""
    changed_paths = {f.path for f in changed}
    out: dict[str, str] = {}
    for f in changed:
        if f.change_kind == "removed" or not (f.path in _HOOK_SOURCES or f.path.endswith("/entry_points.txt")):
            continue
        named = set()
        for ln in (ln for h in f.hunks for ln in h.added):
            s = ln.strip()
            if f.path == "setup.py" and s.startswith(("import ", "from ")):
                named |= execctx.local_imports("setup.py", s.encode("utf-8", "replace"), new_files)
            named |= {p for m in _EP_TARGET.finditer(ln) if (p := execctx.module_file(m.group(1), new_files))}
            named |= {p for m in _PY_PATH.finditer(ln) if (p := m.group(1).removeprefix("./")) in new_files}
        for p in sorted(named):
            if p not in changed_paths and p not in out and len(out) < _MAX_HOOK_TARGETS:
                out[p] = f.path
    return [FileDiff(p, "unchanged", [], new_files[p].decode("utf-8", errors="replace"), run_by=by)
            for p, by in out.items()]


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
    hooks = _hook_targets(a.new_files, changed)
    classes = execctx.classify(a.new_files, [f.path for f in changed] + [h.path for h in hooks])
    return Diff(a.package, a.version, a.prior_version is None, changed,
                list(a.added_binaries), list(a.added_dep_findings), _description(a.description),
                execctx.build(a.new_files, a.too_large),
                a.prior_version if a.prior_error and a.prior_version else "", a.surface_omitted,
                "", requires_python=a.requires_python, file_classes=classes, hook_targets=hooks)
