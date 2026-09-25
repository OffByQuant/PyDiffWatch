import io, gzip, tarfile, hashlib, json, time, urllib.request, urllib.error, posixpath
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from .config import Config
from .models import NewRelease, ArtifactSet
from . import quarantine, deps, egress, execctx

class RefusedToExtract(Exception): ...
class RefusedToFetch(Exception): ...
class MetadataGone(Exception): ...          # PyPI's JSON metadata 404s: the project was removed
class MetadataUnavailable(Exception): ...   # any other metadata failure: retried on later ticks


@dataclass(frozen=True)
class NoSdist:
    """This version has no sdist (wheel-only, or its wheels uploaded before its sdist). `switched_from`: the
    previous release, when it had an sdist — a switch to wheel-only, which dodges an sdist-only scan."""
    switched_from: str | None = None

class _BoundedReader:
    """Forward-only wrapper over a decompressed stream that refuses once cumulative bytes read
    exceed `limit`. tarfile pulls the gzip-decompressed tar through this, so a small blob that
    expands to gigabytes (a PAX long-name record, a lying/oversized header) trips the ceiling
    mid-read — before the giant string is ever fully materialised — instead of OOMing the host."""
    def __init__(self, raw, limit: int):
        self._raw = raw; self._limit = limit; self._n = 0
    def read(self, size=-1):
        chunk = self._raw.read(size)
        self._n += len(chunk)
        if self._n > self._limit:
            raise RefusedToExtract("decompressed-size")
        return chunk

_SRC_EXT = (".py", ".pyx", ".pyi", ".pth")
_SRC_NAMES = {"setup.py", "setup.cfg", "pyproject.toml", "PKG-INFO", "entry_points.txt", "top_level.txt"}
_BIN_EXT = (".so", ".pyd", ".dll", ".dylib")
# Source in another PROGRAMMING language has no legitimate role in a Python sdist — a strong bad-actor
# signal (the cudrequest typosquat shipped a PHP login app). Deliberately conservative: C-ext source
# (.c/.h/.pyx/.pxd), vendored web assets (.js/.css/.html), build scripts (.sh), config and docs are
# all legitimately shipped and are EXCLUDED — flagging them would drown the signal in false positives.
_FOREIGN_EXT = (".php", ".phtml", ".php3", ".php4", ".php5",   # PHP — the cudrequest case
                ".rb", ".gemspec", ".pl", ".pm", ".lua",       # Ruby / Perl / Lua
                ".go", ".java", ".class", ".jar", ".cs", ".vb", # Go / JVM / .NET
                ".ps1", ".psm1", ".bat", ".cmd",                # Windows shell / PowerShell
                ".asp", ".aspx", ".jsp", ".exe")                # server-side web pages / bundled exe

def _is_source(name): return name.lower().endswith(_SRC_EXT) or posixpath.basename(name) in _SRC_NAMES
def _is_binary(name): return name.lower().endswith(_BIN_EXT)
def _foreign_ext(name):
    low = name.lower()
    return next((e for e in _FOREIGN_EXT if low.endswith(e)), None)
def _strip_top(name): return name.split("/", 1)[1] if "/" in name else name
def _unsafe(name): return name.startswith("/") or ".." in name.split("/")

def _sha256_of(fileobj) -> str:
    """Fingerprint a member without holding it in memory (an oversized source can be up to max_member_bytes)."""
    h = hashlib.sha256()
    while chunk := fileobj.read(1 << 20):
        h.update(chunk)
    return h.hexdigest()

def extract_sdist(blob: bytes, cfg: Config):
    files: dict[str, bytes] = {}; binaries: list[dict] = []
    total = 0; count = 0
    if blob[:2] == b"PK":            # a zip (PK\x03\x04, empty PK\x05\x06, spanned PK\x07\x08): never unpacked
        raise RefusedToExtract("zip-sdist")
    # Decompress through a byte-ceiling and read the tar as a forward-only STREAM ("r|"): both
    # bound peak RAM so a malicious sdist cannot expand to gigabytes in memory during extraction.
    # A corrupt or truncated archive raises the stdlib error here or mid-loop; the caller retries it.
    stream = _BoundedReader(gzip.GzipFile(fileobj=io.BytesIO(blob)), cfg.max_decompressed_bytes)
    with tarfile.open(fileobj=stream, mode="r|") as tar:  # streaming; NEVER extractall
        for m in tar:
            count += 1
            if count > cfg.max_members: raise RefusedToExtract("members")
            if len(m.name) > cfg.max_name_bytes or not m.name.isprintable():
                raise RefusedToExtract("member-name")  # name bomb, or control characters (never legitimate)
            if not m.isfile(): continue               # skip dirs/symlinks/devices
            if _unsafe(m.name): continue              # defensive: drop path-escapes
            total += m.size
            if total > cfg.max_total_bytes: raise RefusedToExtract("total-size")
            rel = _strip_top(m.name)
            if _is_source(m.name) and m.size <= cfg.max_source_file_bytes:
                files[rel] = tar.extractfile(m).read(cfg.max_source_file_bytes + 1)
            elif _is_source(m.name):
                # Oversized source: too big to analyze. Record as a signal, never drop silently (spec §8).
                binaries.append({"path": rel, "size": m.size, "reason": "source-too-large",
                                 "sha256": _sha256_of(tar.extractfile(m))})
            elif _is_binary(m.name):
                binaries.append({"path": rel, "sha256": _sha256_of(tar.extractfile(m)), "size": m.size})
            elif fext := _foreign_ext(m.name):
                # Foreign-language source: record presence (path/ext/size) as a signal. We fingerprint
                # the bytes (to drop unchanged files vs the prior release) but never parse or analyze
                # them — this is not Python code we understand. Every one is hashed (streamed); the
                # max_foreign_files cap applies after the prior comparison (_cap_foreign), so unchanged
                # files cannot use it up.
                binaries.append({"path": rel, "size": m.size, "ext": fext,
                                 "reason": "foreign-language-source", "sha256": _sha256_of(tar.extractfile(m))})
            elif m.size > cfg.max_member_bytes:
                # One oversized file is skipped and fingerprinted, not a reason to refuse the sdist (npm #27).
                binaries.append({"path": rel, "size": m.size, "reason": "file-too-large",
                                 "sha256": _sha256_of(tar.extractfile(m))})
    return files, binaries

def _cap_foreign(bins: list[dict], cfg: Config) -> list[dict]:
    """Keep at most max_foreign_files foreign-language records; other records are untouched."""
    out, n = [], 0
    for b in bins:
        if b.get("reason") == "foreign-language-source":
            n += 1
            if n > cfg.max_foreign_files:
                continue
        out.append(b)
    return out

def read_body(r, cfg: Config, limit: int | None = None, deadline: float | None = None) -> bytes:
    """A response body within a total deadline (seconds; default fetch_deadline_s) and an optional size cap.
    urlopen's timeout bounds each socket read only, so a connection that trickles bytes would otherwise
    hold a scan tick forever."""
    budget = deadline or cfg.fetch_deadline_s
    end = time.monotonic() + budget
    buf = bytearray()                             # amortized O(1) append; bytes += is O(n^2)
    while chunk := r.read1(65536):
        buf += chunk
        if limit is not None and len(buf) > limit:
            raise RefusedToFetch("download-size")
        if time.monotonic() > end:
            raise TimeoutError(f"download took longer than {budget:.0f}s")
    return bytes(buf)


def _read_json(r, cfg: Config):
    return json.loads(read_body(r, cfg, cfg.max_metadata_bytes, cfg.packument_deadline_s))


def _download(url: str, cfg: Config) -> bytes:
    egress.assert_web_scheme(url)   # url is from PyPI's JSON — reject file:// before urllib reads a local path
    req = urllib.request.Request(url, headers={"User-Agent": "diffwatch/0.1"})
    with urllib.request.urlopen(req, timeout=cfg.fetch_timeout_s) as r:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        return read_body(r, cfg, cfg.max_download_bytes)

# Files PyPI runs at install or import time — where supply-chain malware must live to execute.
# Mirrors triage.classify_location's 3x-weighted set; a genuinely new package is scanned ONLY here.
_SURFACE_NAMES = {"setup.py", "setup.cfg", "pyproject.toml", "__init__.py",
                  "conftest.py", "sitecustomize.py"}
# The egg-info files the execution-context block reads (execctx._egg_info: `<x>.egg-info/` at the top level or
# under `src/`), each a few names long. Without them the block would tell the reviewer "none" about entry points
# and top-level names the sdist does declare. PKG-INFO stays out: its body is the whole README, and nothing
# here reads it.
_SURFACE_METADATA = {"entry_points.txt", "top_level.txt"}
def _is_surface(path: str) -> bool:
    parts = path.split("/")
    egg_info = (parts[-1] in _SURFACE_METADATA and parts[-2:-1] and parts[-2].endswith(".egg-info")
                and (len(parts) == 2 or (len(parts) == 3 and parts[0] == "src")))
    return (posixpath.basename(path) in _SURFACE_NAMES or path.endswith(".pth") or bool(egg_info)
            or path == "entry_points.txt")          # old-style flit's entry-points-file default, read by execctx

def _pkginfo_summary(files: dict[str, bytes]) -> str | None:
    """`Summary:` from the sdist's own top-level PKG-INFO: this exact version's claim (spec B4). Parsed header-only
    by execctx's never-raise parser; unparseable, absent, blank or old setuptools' "UNKNOWN" is None."""
    data = files.get("PKG-INFO")
    m = execctx.parse_mapping(data, execctx.KINDS["PKG-INFO"]) if data is not None else None
    v = next((v for k, v in (m or {}).items() if k.lower() == "summary"), None)
    return v if isinstance(v, str) and v.strip() not in ("", "UNKNOWN") else None

def _package_json(package: str, cfg: Config) -> dict:
    url = f"{cfg.pypi_base}/pypi/{package}/json"
    egress.assert_web_scheme(url)
    with urllib.request.urlopen(url, timeout=cfg.fetch_timeout_s) as r:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        return _read_json(r, cfg)

def _sdist(files) -> dict | None:
    return next((f for f in (files or []) if f.get("packagetype") == "sdist"), None)

_CORPUS = None
def _corpus() -> set:
    global _CORPUS
    if _CORPUS is None:
        _CORPUS = deps.load_corpus()
    return _CORPUS

def _requires_dist(package: str, version: str, cfg: Config) -> list | None:
    """`info.requires_dist` for an EXACT version (the package-level JSON only carries the latest's); [] when it
    declares none, None when the lookup failed. Never raises."""
    try:
        url = f"{cfg.pypi_base}/pypi/{package}/{version}/json"
        egress.assert_web_scheme(url)
        with urllib.request.urlopen(url, timeout=cfg.fetch_timeout_s) as r:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            reqs = (_read_json(r, cfg).get("info") or {}).get("requires_dist") or []
            return reqs if isinstance(reqs, list) else None    # a string would read as one dep per character
    except Exception:
        return None   # unknown, not empty: the caller screens nothing rather than false-flag

def _dep_json(name: str, cfg: Config):
    """A candidate dependency's PyPI JSON, or None if it does not exist (404 -> dependency-confusion)."""
    try:
        url = f"{cfg.pypi_base}/pypi/{name}/json"
        egress.assert_web_scheme(url)
        with urllib.request.urlopen(url, timeout=cfg.fetch_timeout_s) as r:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            return _read_json(r, cfg)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        return {}   # transient/other error -> treat as 'exists, unknown age' (never false 'nonexistent')
    except Exception:
        return {}

def _screen_added_deps(meta: dict, package: str, pred_version: str | None, cfg: Config,
                       change: dict | None = None, version: str | None = None) -> list[dict]:
    """Diff the new version's declared deps against the predecessor's and flag suspicious additions.
    The new side comes free from the package-level `info` when it is this `version`'s (the latest); for any
    other release (backfill, retry, --recent, superseded) it is read from the exact version's JSON, and when
    that is unavailable nothing is screened. No new deps -> no predecessor lookup.
    `change`, when passed, receives the added and removed Requires-Dist lines as written (for the reviewer)."""
    info = meta.get("info") or {}
    if version is not None and info.get("version") not in (None, version):
        new_lines = _requires_dist(package, version, cfg) or []   # unknown or empty: screen nothing
    else:
        new_lines = info.get("requires_dist") or []
        new_lines = new_lines if isinstance(new_lines, list) else []
    new_reqs = deps.parse_requires_dist(new_lines)
    if not new_reqs:
        return []
    prior_lines = _requires_dist(package, pred_version, cfg) if pred_version else []
    if prior_lines is None:
        return []           # the predecessor's list is unknown: every dep would read as "added"
    prior_reqs = deps.parse_requires_dist(prior_lines)
    added = new_reqs - prior_reqs
    if change is not None:
        change["added"] = [ln for ln in new_lines if deps.parse_requires_dist([ln]) & added]
        change["removed"] = [ln for ln in prior_lines if deps.parse_requires_dist([ln]) & (prior_reqs - new_reqs)]
    if not added:
        return []
    return deps.screen_added_deps(added, _corpus(), fetch_json=lambda n: _dep_json(n, cfg),
                                  now=datetime.now(timezone.utc), brandnew_days=cfg.dep_brandnew_days,
                                  cap=cfg.max_dep_lookups)

def _maintainer_metadata(meta: dict, new_sd: dict | None) -> dict:
    """Maintainer identity captured from the package JSON we already fetched — author/maintainer names,
    the current ownership usernames, and this version's upload time (for burst analysis later). Emails
    are deliberately omitted (PII; names + roles suffice for maintainer-set-change detection). PyPI does
    NOT expose account creation date here, so account-age is out of scope for this signal."""
    info = meta.get("info") or {}
    return {
        "author": info.get("author"),
        "maintainer": info.get("maintainer"),
        "roles": [r.get("user") for r in (meta.get("ownership", {}) or {}).get("roles", []) or []],
        "upload_time": (new_sd or {}).get("upload_time_iso_8601"),
    }

def _pick_predecessor(meta: dict, version: str):
    """The most recently uploaded OTHER version with a non-yanked sdist, uploaded before `version`.
    Returns (pred_version, pred_sdist_url), or None when `version` is the first-ever sdist release —
    i.e. a genuinely new package. Upload-time ordering avoids a PEP 440 dependency; PyPI's ISO-8601
    UTC timestamps sort correctly as plain strings."""
    releases = meta.get("releases", {})
    tgt = _sdist(releases.get(version))
    tgt_ts = tgt.get("upload_time_iso_8601") if tgt else None
    best = None   # (ts, version, url)
    for ver, files in releases.items():
        if ver == version:
            continue
        f = _sdist(files)
        if not f or f.get("yanked"):
            continue
        ts = f.get("upload_time_iso_8601")
        if not ts or (tgt_ts is not None and ts >= tgt_ts):
            continue
        if best is None or ts > best[0]:
            best = (ts, ver, f.get("url"))
    return (best[1], best[2]) if best else None

def _switched_from(releases: dict, version: str) -> str | None:
    """The release uploaded just before `version` (by each release's first file upload), if it had an sdist.
    Read from the package JSON already fetched, so it is right on a fresh database too."""
    def first(files):
        return min((f["upload_time_iso_8601"] for f in files or [] if f.get("upload_time_iso_8601")), default=None)
    t = first(releases.get(version))
    if t is None:
        return None
    prev = max(((ts, v) for v, files in releases.items() if v != version
                and (ts := first(files)) is not None and ts < t), default=None)
    return prev[1] if prev and _sdist(releases[prev[1]]) else None

def fetch_artifacts(cfg, rel: NewRelease, attempt: int = 1) -> ArtifactSet | NoSdist:
    """Fetch + extract the sdist(s) for one release. The baseline is resolved from PyPI's version
    history (the package JSON), NOT our DB: an UPDATE (a prior version exists) is diffed against its
    predecessor; a genuinely NEW package (no prior) is handled per cfg.new_package_policy.
    Attempt k (a retry) gives the package JSON and the sdist downloads k times their deadlines. The
    requires_dist and dependency lookups keep theirs: they swallow every error, so more time can't turn a
    failure into a success, only lengthen the retry."""
    slow = cfg if attempt <= 1 else replace(cfg, fetch_deadline_s=cfg.fetch_deadline_s * attempt,
                                            packument_deadline_s=cfg.packument_deadline_s * attempt)
    if quarantine.is_quarantined(rel.package):
        # Confirmed supply-chain malware — refuse before any byte is pulled. Maps to a terminal
        # 'refused_to_fetch' stage upstream; DiffWatch never re-ingests it. (§6 / quarantine.py)
        raise RefusedToFetch(f"quarantined: {rel.package}")
    try:
        meta = _package_json(rel.package, slow)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise MetadataGone(f"{rel.package}: PyPI metadata returned 404") from e
        raise MetadataUnavailable(f"{rel.package}: PyPI metadata returned HTTP {e.code}") from e
    except RefusedToFetch:
        raise                                         # over the size cap: a deterministic refusal
    except Exception as e:
        raise MetadataUnavailable(f"{rel.package}: {type(e).__name__}: {e}") from e
    new_sd = _sdist(meta.get("releases", {}).get(rel.version))
    if not new_sd:
        return NoSdist(_switched_from(meta.get("releases", {}), rel.version))   # wheel-only: not scanned
    pred = _pick_predecessor(meta, rel.version)
    is_new = pred is None
    mtmeta = _maintainer_metadata(meta, new_sd)
    info = meta.get("info") or {}
    # The package-level JSON carries the LATEST version's info; another version's claim is not this one's.
    summary = info.get("summary") if info.get("version") == rel.version else None

    if is_new and cfg.new_package_policy == "skip":
        # New package, skip policy: don't even download — but still record who shipped it, so a later
        # version of this package has a maintainer baseline to diff against (maintainer-set-change).
        return ArtifactSet(rel.package, rel.version, None, "sdist", {}, {}, {}, [],
                           is_new_package=True, maintainer_metadata=mtmeta, description=summary)

    new_files, new_bins = extract_sdist(_download(new_sd["url"], slow), cfg)
    summary = _pkginfo_summary(new_files) or summary     # before the surface filter drops PKG-INFO
    # Before the prior comparison drops unchanged ones: the execution context must know an oversized
    # setup.py is there even when it did not change (padding it must not read as "absent").
    too_large = tuple(b["path"] for b in new_bins if b.get("reason") == "source-too-large")
    prior_files: dict[str, bytes] = {}
    prior_bins = None
    prior_ver = None
    prior_error = None
    dep_findings: list[dict] = []
    surface_omitted = None
    req_change: dict = {}
    if is_new:
        if cfg.new_package_policy == "surface":
            # Scan only the install/import-time surface — small, never truncated, high-value.
            n = len(new_files)
            new_files = {p: b for p, b in new_files.items() if _is_surface(p)}
            surface_omitted = n - len(new_files)          # the reviewer is told these exist (B11)
        # "full": keep the whole tree (legacy whole-codebase scan)
    else:
        prior_ver, prior_url = pred
        try:
            prior_files, prior_bins = extract_sdist(_download(prior_url, slow), cfg)
        except Exception as e:     # as npm does: diff against nothing (every file reported), and say so
            prior_error = f"prior {prior_ver} sdist unavailable ({type(e).__name__}: {e}); diffed against nothing"
        if prior_bins is not None:
            # Only what this release adds or changes is a signal; an unchanged oversized/binary/foreign
            # file republished release after release is not.
            same = {(b["path"], b.get("sha256")) for b in prior_bins if b.get("sha256")}
            new_bins = [b for b in new_bins if (b["path"], b.get("sha256")) not in same]
        # signal 5: flag suspicious newly-added dependencies vs the predecessor (update path only).
        dep_findings = _screen_added_deps(meta, rel.package, prior_ver, cfg, change=req_change, version=rel.version)
    return ArtifactSet(rel.package, rel.version, prior_ver, "sdist",
                       new_files, prior_files, {}, _cap_foreign(new_bins, cfg),
                       is_new_package=is_new, maintainer_metadata=mtmeta,
                       added_dep_findings=dep_findings, prior_error=prior_error, description=summary,
                       too_large=too_large, surface_omitted=surface_omitted,
                       requires_dist_change=req_change if any(req_change.values()) else None)
