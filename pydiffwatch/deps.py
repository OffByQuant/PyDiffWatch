"""Added-dependency reputation gate (detection-signals roadmap signal 5).

Pure logic + an injected network fetch. The egress (fetcher) injects a real `fetch_json`; triage
scores the findings this returns. A new version pulling in a dependency is benign almost always, so
the gate is REPUTATION-based: an established, popular dep (in the vendored top-PyPI corpus) is cleared
with NO network call; only suspicious names (typosquat-close / nonexistent / brand-new) are flagged.
No vet-mcp — vet is a peer scanner; depending on it for detection makes DiffWatch downstream/too-late.
"""
import os
import re
from datetime import datetime, timezone

_CORPUS_PATH = os.path.join(os.path.dirname(__file__), "data", "top_pypi_names.txt")
_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")   # leading token of a Requires-Dist line
_MIN_TYPOSQUAT_LEN = 5   # don't flag distance-1 noise on very short names (<=4 chars)


def normalize_name(name: str) -> str:
    """PEP 503 canonical form: lowercase, runs of -_. collapsed to a single hyphen."""
    return re.sub(r"[-_.]+", "-", name).strip().lower()


def parse_requires_dist(lines) -> set[str]:
    """Bare, normalized project names from `Requires-Dist` values (extras/markers/specifiers stripped)."""
    names = set()
    for line in lines or []:
        m = _NAME_RE.match(line.strip())
        if m:
            names.add(normalize_name(m.group(0)))
    return names


def load_corpus(path: str | None = None) -> set[str]:
    """The vendored top-PyPI names (popularity whitelist + typosquat target). Comments/blanks skipped."""
    out = set()
    with open(path or _CORPUS_PATH, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                out.add(normalize_name(line))
    return out


def edit_distance(a: str, b: str) -> int:
    """Levenshtein distance (iterative two-row)."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def nearest_corpus(name: str, corpus, max_dist: int = 2) -> str | None:
    """The closest popular name within [1, max_dist] of `name`, or None. Exact matches (it IS the
    popular package) and very short names (distance-1 noise) are excluded. Length-windowed for speed."""
    if len(name) < _MIN_TYPOSQUAT_LEN or name in corpus:
        return None
    best, best_d = None, max_dist + 1
    for c in corpus:
        if abs(len(c) - len(name)) > max_dist:      # necessary condition for dist<=max_dist; prunes most
            continue
        d = edit_distance(name, c)
        if 1 <= d < best_d:
            best, best_d = c, d
            if d == 1:
                break
    return best


def screen_added_deps(added, corpus, *, fetch_json, now=None, brandnew_days: int = 30,
                      cap: int = 10, cache: dict | None = None) -> list[dict]:
    """Classify each added (normalized) dep name. Returns a finding dict per suspicious dep:
      {"name", "reason": "typosquat", "target"} | {"name", "reason": "nonexistent"} |
      {"name", "reason": "brand-new"} | {"name", "reason": "not-screened-cap"}.
    Established/popular deps (in corpus) and mature existing deps produce NO finding. `fetch_json(name)`
    returns the parsed /pypi/{name}/json dict, or None for a 404. Network is bounded to `cap` fetches;
    overflow deps are RECORDED (never silently dropped). `cache` (name -> json|None) skips re-fetches."""
    now = now or datetime.now(timezone.utc)
    cache = cache if cache is not None else {}
    findings, fetched = [], 0
    for name in sorted(added):
        if name in corpus:
            continue                                 # popular -> reputable, no fetch, no flag
        target = nearest_corpus(name, corpus)
        if target:
            findings.append({"name": name, "reason": "typosquat", "target": target})
            continue                                 # decided locally, no network
        if name not in cache:
            if fetched >= cap:
                findings.append({"name": name, "reason": "not-screened-cap"})
                continue
            cache[name] = fetch_json(name)
            fetched += 1
        meta = cache[name]
        if meta is None:
            findings.append({"name": name, "reason": "nonexistent"})
            continue
        earliest = _earliest_upload(meta)
        if earliest is not None and (now - earliest).days < brandnew_days:
            findings.append({"name": name, "reason": "brand-new"})
    return findings


def _earliest_upload(meta: dict):
    """Earliest release upload time across all versions, or None if unavailable."""
    times = []
    for files in (meta.get("releases") or {}).values():
        for f in files or []:
            ts = f.get("upload_time_iso_8601")
            if ts:
                try:
                    times.append(datetime.fromisoformat(ts.replace("Z", "+00:00")))
                except ValueError:
                    pass
    return min(times) if times else None
