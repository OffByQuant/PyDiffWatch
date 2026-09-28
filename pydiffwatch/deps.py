"""Added-dependency reputation gate (detection-signals roadmap signal 5).

Pure logic + an injected network fetch. The egress (fetcher) injects a real `fetch_json`; triage
scores the findings this returns. A new version pulling in a dependency is benign almost always, so
the gate is REPUTATION-based: an established, popular dep (in the vendored top-PyPI corpus) is cleared
with NO network call; only suspicious names (typosquat-close / nonexistent / brand-new) are flagged.
No vet-mcp — vet is a peer scanner; depending on it for detection makes DiffWatch downstream/too-late.
"""
import email.utils
import logging
import os
import re
import urllib.parse
from datetime import datetime, timezone

_CORPUS_PATH = os.path.join(os.path.dirname(__file__), "data", "top_pypi_names.txt")
_ORGS_PATH = os.path.join(os.path.dirname(__file__), "data", "top_pypi_orgs.txt")
_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")   # leading token of a Requires-Dist line
_MIN_TYPOSQUAT_LEN = 5   # don't flag distance-1 noise on very short names (<=4 chars)
_ESTABLISHED_DAYS = 365       # a typosquat-close dep this old AND with this many releases is not a fresh squat
_ESTABLISHED_RELEASES = 5
MIN_ORG_PACKAGES = 2          # an organisation must own this many top-PyPI packages to clear a lookalike dep
_CODE_HOSTS = {"github.com", "gitlab.com", "codeberg.org", "bitbucket.org"}

logger = logging.getLogger(__name__)


def identity(meta) -> dict:
    """Who a package's PyPI JSON says it is: owners (verified PyPI accounts), author/maintainer emails and code-host
    orgs (both author-declared). Emails are compared in memory only; never stored, logged or rendered."""
    meta = meta if isinstance(meta, dict) else {}
    info = meta.get("info") if isinstance(meta.get("info"), dict) else {}
    own = meta.get("ownership") if isinstance(meta.get("ownership"), dict) else {}
    roles = own.get("roles") if isinstance(own.get("roles"), list) else []
    out = {"roles": {r["user"].lower() for r in roles if isinstance(r, dict) and isinstance(r.get("user"), str)},
           "emails": set(), "orgs": set()}
    fields = [v for v in (info.get("author_email"), info.get("maintainer_email")) if isinstance(v, str)]
    for _, addr in email.utils.getaddresses(fields):
        if "@" in addr:
            out["emails"].add(addr.strip().lower())
    urls = info.get("project_urls")
    urls = list(urls.values()) if isinstance(urls, dict) else []
    for u in urls + [info.get("home_page")]:
        if not isinstance(u, str):
            continue
        try:
            p = urllib.parse.urlsplit(u)
        except ValueError:
            continue
        seg = p.path.strip("/").split("/")[0].lower()
        if (p.hostname or "").lower() in _CODE_HOSTS and seg:
            out["orgs"].add((p.hostname.lower(), seg))
    return out


def _release_count(meta) -> int:
    rel = meta.get("releases") if isinstance(meta, dict) else None
    return sum(1 for files in (rel.values() if isinstance(rel, dict) else ()) if isinstance(files, list) and files)


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


def org_of(meta) -> str | None:
    """The PyPI organisation in a package's JSON (`ownership.organization`), PEP 503-normalized; None when absent.
    PyPI vets only an organisation's name, so this proves nothing alone: see load_popular_orgs."""
    own = meta.get("ownership") if isinstance(meta, dict) else None
    org = own.get("organization") if isinstance(own, dict) else None
    return (normalize_name(org) or None) if isinstance(org, str) else None


def load_popular_orgs(path: str | None = None, min_packages: int = MIN_ORG_PACKAGES) -> frozenset[str]:
    """Organisations owning at least `min_packages` top-PyPI packages, from the vendored `org<TAB>package` map
    (tools/build_top_orgs.py). Whoever controls such an organisation already controls popular packages, so a
    lookalike dependency it publishes is not read as a typosquat. A missing file gives an empty set (today's
    behaviour), and so does an unreadable one; comments, blanks, duplicates and lines without exactly two
    tab-separated columns are skipped."""
    pkgs = {}
    try:
        with open(path or _ORGS_PATH, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("\t")
                if len(parts) != 2:
                    continue
                org, pkg = normalize_name(parts[0]), normalize_name(parts[1])
                if org and pkg:
                    pkgs.setdefault(org, set()).add(pkg)
    except (OSError, UnicodeDecodeError) as e:
        logger.warning("no usable PyPI organisation map at %s (%s); organisation-owned lookalike deps stay flagged",
                       path or _ORGS_PATH, type(e).__name__)
        return frozenset()
    return frozenset(o for o, p in pkgs.items() if len(p) >= min_packages)


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
                      cap: int = 10, cache: dict | None = None, own: dict | None = None,
                      orgs: frozenset = frozenset()) -> list[dict]:
    """Classify each added (normalized) dep name. Established/popular deps (in corpus) produce no finding and no
    fetch. A name within 2 edits of the corpus is looked up (PR E): a shared PyPI owner with `own` (the scanned
    package's identity) or age >= _ESTABLISHED_DAYS with >= _ESTABLISHED_RELEASES releases clears the typosquat
    reading; author-declared matches only annotate. A capped or failed lookup keeps the plain typosquat finding.
    `fetch_json(name)` returns the /pypi/{name}/json dict, None for a 404, {} on a transient error. Network is
    bounded to `cap` fetches; `cache` (name -> json|None) skips re-fetches. `orgs` (load_popular_orgs): a candidate
    whose PyPI organisation is in it is cleared like a shared owner, before the target is looked up; a brand-new
    finding then carries that `pypi_org`."""
    now = now or datetime.now(timezone.utc)
    cache = cache if cache is not None else {}
    own = own or {"roles": set(), "emails": set(), "orgs": set()}
    findings, fetched = [], 0

    def lookup(name):
        nonlocal fetched
        if name not in cache:
            if fetched >= cap:
                return "capped"
            got = fetch_json(name)
            cache[name] = got if got is None or isinstance(got, dict) else {}   # non-dict JSON reads as no data
            fetched += 1
        return cache[name]

    for name in sorted(added):
        if name in corpus:
            continue                                 # popular -> reputable, no fetch, no flag
        target = nearest_corpus(name, corpus)
        meta = lookup(name)
        if meta == "capped":
            findings.append({"name": name, "reason": "typosquat", "target": target} if target
                            else {"name": name, "reason": "not-screened-cap"})
            continue
        if meta is None:
            findings.append({"name": name, "reason": "nonexistent", **({"target": target} if target else {})})
            continue
        same_owner = False
        org = org_of(meta)
        popular_org = org if org in orgs else None
        if target:
            if not meta:
                findings.append({"name": name, "reason": "typosquat", "target": target})   # never cleared on no data
                continue
            ident = identity(meta)
            same_owner = bool(ident["roles"] and own["roles"] and ident["roles"] & own["roles"])
            if not same_owner and not popular_org:
                earliest, n = _earliest_upload(meta), _release_count(meta)
                if earliest is not None and (now - earliest).days >= _ESTABLISHED_DAYS and n >= _ESTABLISHED_RELEASES:
                    continue
                tmeta = lookup(target) if ident["emails"] else None   # nothing to compare: spend no GET
                tident = identity(tmeta) if isinstance(tmeta, dict) and tmeta else None
                findings.append({
                    "name": name, "reason": "typosquat", "target": target,
                    "first_upload": earliest.date().isoformat() if earliest else None, "releases": n,
                    "owner": "different" if ident["roles"] and own["roles"] else "unknown",
                    "same_author_email": bool(ident["emails"] & own["emails"]),
                    "same_org": bool(ident["orgs"] & own["orgs"]),
                    "same_author_as_target": bool(tident and ident["emails"] & tident["emails"]),
                    "pypi_org": org})
                continue
        if not meta:
            continue                                 # a transient error on a non-candidate: unknown age, no flag
        earliest = _earliest_upload(meta)
        if earliest is not None and (now - earliest).days < brandnew_days:
            findings.append({"name": name, "reason": "brand-new", **({"same_owner": True} if same_owner else {}),
                             **({"pypi_org": popular_org} if popular_org else {})})
    return findings


def _earliest_upload(meta: dict):
    """Earliest release upload time across all versions, or None if unavailable."""
    times = []
    rel = meta.get("releases") if isinstance(meta, dict) else None
    for files in (rel.values() if isinstance(rel, dict) else ()):
        for f in files if isinstance(files, list) else ():
            ts = f.get("upload_time_iso_8601") if isinstance(f, dict) else None
            if isinstance(ts, str):
                try:
                    times.append(datetime.fromisoformat(ts.replace("Z", "+00:00")))
                except ValueError:
                    pass
    return min(times) if times else None
