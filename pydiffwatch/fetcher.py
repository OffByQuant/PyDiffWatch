import io, gzip, tarfile, hashlib, json, urllib.request, urllib.error, posixpath
from datetime import datetime, timezone
from .config import Config
from .models import NewRelease, ArtifactSet
from . import quarantine, deps

class RefusedToExtract(Exception): ...
class RefusedToFetch(Exception): ...

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

_SRC_EXT = (".py", ".pyx", ".pyi")
_SRC_NAMES = {"setup.py", "setup.cfg", "pyproject.toml", "PKG-INFO"}
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

def _is_source(name): return name.endswith(_SRC_EXT) or posixpath.basename(name) in _SRC_NAMES
def _is_binary(name): return name.endswith(_BIN_EXT)
def _foreign_ext(name):
    low = name.lower()
    return next((e for e in _FOREIGN_EXT if low.endswith(e)), None)
def _strip_top(name): return name.split("/", 1)[1] if "/" in name else name
def _unsafe(name): return name.startswith("/") or ".." in name.split("/")

def extract_sdist(blob: bytes, cfg: Config):
    files: dict[str, bytes] = {}; binaries: list[dict] = []
    total = 0; count = 0; foreign = 0
    # Decompress through a byte-ceiling and read the tar as a forward-only STREAM ("r|"): both
    # bound peak RAM so a malicious sdist cannot expand to gigabytes in memory during extraction.
    stream = _BoundedReader(gzip.GzipFile(fileobj=io.BytesIO(blob)), cfg.max_decompressed_bytes)
    try:
        tar = tarfile.open(fileobj=stream, mode="r|")  # streaming; NEVER extractall
    except (tarfile.ReadError, OSError, EOFError) as e:
        raise RefusedToExtract(f"bad-archive: {e}") from e
    with tar:
        for m in tar:
            count += 1
            if count > cfg.max_members: raise RefusedToExtract("members")
            if len(m.name) > cfg.max_name_bytes: raise RefusedToExtract("member-name")  # name bomb
            if not m.isfile(): continue               # skip dirs/symlinks/devices
            if _unsafe(m.name): continue              # defensive: drop path-escapes
            if m.size > cfg.max_member_bytes: raise RefusedToExtract("member-size")
            total += m.size
            if total > cfg.max_total_bytes: raise RefusedToExtract("total-size")
            rel = _strip_top(m.name)
            if _is_source(m.name) and m.size <= cfg.max_source_file_bytes:
                files[rel] = tar.extractfile(m).read(cfg.max_source_file_bytes + 1)
            elif _is_source(m.name):
                # Oversized source: too big to analyze. Record as a signal, never drop silently (spec §8).
                binaries.append({"path": rel, "size": m.size, "reason": "source-too-large"})
            elif _is_binary(m.name):
                data = tar.extractfile(m).read()
                binaries.append({"path": rel, "sha256": hashlib.sha256(data).hexdigest(),
                                 "size": m.size})
            elif (fext := _foreign_ext(m.name)) and foreign < cfg.max_foreign_files:
                # Foreign-language source: record presence (path/ext/size) as a signal — NEVER read the
                # bytes (cheap, and we don't execute or analyze non-Python code). Cap-and-stop.
                binaries.append({"path": rel, "size": m.size, "ext": fext,
                                 "reason": "foreign-language-source"})
                foreign += 1
    return files, binaries

def _download(url: str, cfg: Config) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "diffwatch/0.1"})
    with urllib.request.urlopen(req, timeout=cfg.fetch_timeout_s) as r:
        buf = bytearray()                             # amortized O(1) append; bytes += is O(n^2)
        while chunk := r.read(65536):
            buf += chunk
            if len(buf) > cfg.max_download_bytes: raise RefusedToFetch("download-size")
        return bytes(buf)

# Files PyPI runs at install or import time — where supply-chain malware must live to execute.
# Mirrors triage.classify_location's 3x-weighted set; a genuinely new package is scanned ONLY here.
_SURFACE_NAMES = {"setup.py", "setup.cfg", "pyproject.toml", "__init__.py",
                  "conftest.py", "sitecustomize.py"}
def _is_surface(path: str) -> bool:
    return posixpath.basename(path) in _SURFACE_NAMES or path.endswith(".pth")

def _package_json(package: str, cfg: Config) -> dict:
    url = f"{cfg.pypi_base}/pypi/{package}/json"
    with urllib.request.urlopen(url, timeout=cfg.fetch_timeout_s) as r:
        return json.load(r)

def _sdist(files) -> dict | None:
    return next((f for f in (files or []) if f.get("packagetype") == "sdist"), None)

_CORPUS = None
def _corpus() -> set:
    global _CORPUS
    if _CORPUS is None:
        _CORPUS = deps.load_corpus()
    return _CORPUS

def _requires_dist(package: str, version: str, cfg: Config) -> list:
    """`info.requires_dist` for an EXACT version (the package-level JSON only carries the latest's)."""
    try:
        url = f"{cfg.pypi_base}/pypi/{package}/{version}/json"
        with urllib.request.urlopen(url, timeout=cfg.fetch_timeout_s) as r:
            return (json.load(r).get("info") or {}).get("requires_dist") or []
    except Exception:
        return []   # can't resolve predecessor deps -> screen nothing rather than false-flag

def _dep_json(name: str, cfg: Config):
    """A candidate dependency's PyPI JSON, or None if it does not exist (404 -> dependency-confusion)."""
    try:
        url = f"{cfg.pypi_base}/pypi/{name}/json"
        with urllib.request.urlopen(url, timeout=cfg.fetch_timeout_s) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        return {}   # transient/other error -> treat as 'exists, unknown age' (never false 'nonexistent')
    except Exception:
        return {}

def _screen_added_deps(meta: dict, package: str, pred_version: str | None, cfg: Config) -> list[dict]:
    """Diff the new version's declared deps against the predecessor's and flag suspicious additions.
    new-side deps come free from the package-level `info` (the firehose release is normally the latest;
    a rare lag mis-reads them, an accepted v1 approximation). Empty additions -> zero network."""
    new_reqs = deps.parse_requires_dist((meta.get("info") or {}).get("requires_dist") or [])
    if not new_reqs:
        return []
    prior_reqs = deps.parse_requires_dist(_requires_dist(package, pred_version, cfg)) if pred_version else set()
    added = new_reqs - prior_reqs
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

def fetch_artifacts(cfg, rel: NewRelease) -> ArtifactSet | None:
    """Fetch + extract the sdist(s) for one release. The baseline is resolved from PyPI's version
    history (the package JSON), NOT our DB: an UPDATE (a prior version exists) is diffed against its
    predecessor; a genuinely NEW package (no prior) is handled per cfg.new_package_policy."""
    if quarantine.is_quarantined(rel.package):
        # Confirmed supply-chain malware — refuse before any byte is pulled. Maps to a terminal
        # 'refused_to_fetch' stage upstream; DiffWatch never re-ingests it. (§6 / quarantine.py)
        raise RefusedToFetch(f"quarantined: {rel.package}")
    meta = _package_json(rel.package, cfg)
    new_sd = _sdist(meta.get("releases", {}).get(rel.version))
    if not new_sd:
        return None                                   # no sdist for this version (wheel-only; Phase 3)
    pred = _pick_predecessor(meta, rel.version)
    is_new = pred is None
    mtmeta = _maintainer_metadata(meta, new_sd)

    if is_new and cfg.new_package_policy == "skip":
        # New package, skip policy: don't even download — but still record who shipped it, so a later
        # version of this package has a maintainer baseline to diff against (maintainer-set-change).
        return ArtifactSet(rel.package, rel.version, None, "sdist", {}, {}, {}, [],
                           is_new_package=True, maintainer_metadata=mtmeta)

    new_files, new_bins = extract_sdist(_download(new_sd["url"], cfg), cfg)
    prior_files: dict[str, bytes] = {}
    prior_ver = None
    dep_findings: list[dict] = []
    if is_new:
        if cfg.new_package_policy == "surface":
            # Scan only the install/import-time surface — small, never truncated, high-value.
            new_files = {p: b for p, b in new_files.items() if _is_surface(p)}
        # "full": keep the whole tree (legacy whole-codebase scan)
    else:
        prior_ver, prior_url = pred
        prior_files, _ = extract_sdist(_download(prior_url, cfg), cfg)
        # signal 5: flag suspicious newly-added dependencies vs the predecessor (update path only).
        dep_findings = _screen_added_deps(meta, rel.package, prior_ver, cfg)
    return ArtifactSet(rel.package, rel.version, prior_ver, "sdist",
                       new_files, prior_files, {}, new_bins,
                       is_new_package=is_new, maintainer_metadata=mtmeta,
                       added_dep_findings=dep_findings)
