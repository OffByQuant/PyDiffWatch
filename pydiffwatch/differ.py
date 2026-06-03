import difflib
from .models import ArtifactSet, Diff, FileDiff, Hunk

def _lines(b: bytes) -> list[str]:
    return b.decode("utf-8", errors="replace").splitlines()

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
                list(a.added_binaries), list(a.added_dep_findings))
