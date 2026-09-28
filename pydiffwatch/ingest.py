"""Firehose source: PyPI's PEP 691 JSON simple index (`/simple/`: every project and its `_last-serial`), then the
JSON of each project that changed since the cursor. PyPI's XML-RPC changelog is deprecated ("planned for
deprecation", docs.pypi.org/api/) and returned 503 from 2026-09-28; this replaces it. The cursor stays a serial.
A removal no longer arrives as an event: the fetcher's 404 path (fetcher.Removed) catches it, so `removed_at`
stays None."""
import datetime
import email.message
import gzip
import io
import json
import logging
import re
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from .config import Config
from .fetcher import RefusedToFetch, read_body
from .models import NewRelease

logger = logging.getLogger(__name__)

INDEX_ACCEPT = "application/vnd.pypi.simple.v1+json"
_UA = "diffwatch/0.1"
_ENTRY = re.compile(r"\{[^{}]*\}")                       # one flat project object (or the meta object)
_SERIAL = re.compile(r'"_last-serial"\s*:\s*(\d+)')
_META = re.compile(r'"meta"\s*:\s*(\{[^{}]*\})')


class Changes(list):
    """Releases a poll found, in ascending serial, plus `ceiling`: the highest serial the cursor may reach once
    every listed release is terminal (the index's own serial, lowered below any project this poll could not
    resolve, or cut by a per-run cap). A plain list (a test stub) has no ceiling: the cursor then advances only
    to listed serials. `complete`: True only when the ceiling reached the index's own serial untouched — no
    project was held, stale or cut, and no release cap lowered it (Task 3 uses this to decide whether the
    poll fully caught the index up)."""
    ceiling: int | None = None
    complete: bool = False


def _get(cfg: Config, url: str, headers: dict, limit: int, deadline: float):
    """(status, headers, body) of one GET within a size cap and a total deadline. Raises urllib.error.HTTPError
    (a 304 included) and URLError/OSError/TimeoutError as urllib does."""
    req = urllib.request.Request(url, headers={"User-Agent": _UA, **headers})
    with urllib.request.urlopen(req, timeout=cfg.fetch_timeout_s) as r:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        return r.status, r.headers, read_body(r, cfg, limit, deadline)


def _gunzip(data: bytes, cap: int) -> bytes:
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as g:
        out = g.read(cap + 1)
    if len(out) > cap:
        raise ValueError(f"simple index decodes past {cap} bytes")
    return out


def _index_text(cfg: Config) -> str:
    """The decoded /simple/ JSON. A conditional GET: the gzip body and its ETag are cached next to the lock file,
    and a 304 reuses the cache (PyPI serves the index with max-age=600, so most ticks cost one small request)."""
    state = cfg.lock_path.parent
    gz_path, tag_path = state / "simple-index.json.gz", state / "simple-index.etag"
    headers = {"Accept": INDEX_ACCEPT, "Accept-Encoding": "gzip"}
    if gz_path.exists() and tag_path.exists():
        headers["If-None-Match"] = tag_path.read_text().strip()
    try:
        _, hdrs, body = _get(cfg, f"{cfg.pypi_base}/simple/", headers, cfg.max_index_bytes, cfg.packument_deadline_s)
    except urllib.error.HTTPError as e:
        if e.code != 304:
            raise
        return _gunzip(gz_path.read_bytes(), cfg.max_index_bytes).decode()
    gz = body if (hdrs.get("Content-Encoding") or "").lower() == "gzip" else gzip.compress(body)
    text = _gunzip(gz, cfg.max_index_bytes).decode()
    state.mkdir(parents=True, exist_ok=True)
    gz_path.write_bytes(gz)
    if etag := hdrs.get("ETag"):
        tag_path.write_text(etag)
    else:
        tag_path.unlink(missing_ok=True)
    return text


def _changed(text: str, since: int) -> tuple[int, list[tuple[int, str]]]:
    """(the index's own serial, [(serial, name)] of projects with `_last-serial` > since, ascending). Scans flat
    `{...}` objects with a regex and json-decodes only the ones above the cursor, so the ~900k-entry document is
    never loaded whole. Raises ValueError when the meta serial is missing (a truncated or foreign body)."""
    m = _META.search(text)
    meta = json.loads(m.group(1)).get("_last-serial") if m else None
    if not isinstance(meta, int) or isinstance(meta, bool):
        raise ValueError("simple index has no meta._last-serial")
    out = []
    for e in _ENTRY.finditer(text):
        obj = e.group()
        s = _SERIAL.search(obj)
        if not s or int(s.group(1)) <= since:
            continue
        try:
            d = json.loads(obj)
        except ValueError:
            continue
        serial, name = d.get("_last-serial"), d.get("name")
        if isinstance(serial, int) and not isinstance(serial, bool) and isinstance(name, str) and name:
            out.append((serial, name))
    out.sort()
    return meta, out


def _head_serial(cfg: Config) -> int:
    req = urllib.request.Request(f"{cfg.pypi_base}/simple/", method="HEAD",
                                 headers={"User-Agent": _UA, "Accept": INDEX_ACCEPT})
    with urllib.request.urlopen(req, timeout=cfg.fetch_timeout_s) as r:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        return int(r.headers["X-PyPI-Last-Serial"])


def current_serial(cfg: Config) -> int | None:
    """PyPI's current serial (the index's X-PyPI-Last-Serial), for 'start monitoring from now' cursor seeding.
    None on failure so the caller skips and retries rather than crawl from genesis."""
    try:
        return _head_serial(cfg)
    except Exception:
        return None


_WHEEL_ONLY = ("no_sdist", "no_sdist_wait")


def _when(ts):
    """An aware UTC datetime from PyPI's `upload_time_iso_8601` (or our stored floor); None when unparseable.
    Compared as datetimes, never as strings: `...Z` and `...+00:00` do not sort alike."""
    if not isinstance(ts, str):
        return None
    try:
        dt = datetime.datetime.fromisoformat(ts)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=datetime.UTC)


def _fetch_summary(cfg: Config, name: str):
    """Fetch one project's /pypi/<name>/json and reduce it to (served serial, display name, {version: (first
    upload as an aware datetime, has an sdist)}) — never the parsed JSON itself, so the thread pool never holds
    every changed project's full document at once (a big project's JSON runs several MB, and a tick may fetch
    up to `max_projects_per_run` of them). (None, None, None) for a 404. Malformed shapes give an empty version
    map; versions with no parseable upload time are skipped."""
    try:
        _, hdrs, body = _get(cfg, f"{cfg.pypi_base}/pypi/{urllib.parse.quote(name, safe='')}/json",
                             {"Accept": "application/json"}, cfg.max_metadata_bytes, cfg.packument_deadline_s)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None, None, None
        raise
    data = json.loads(body)
    raw = hdrs.get("X-PyPI-Last-Serial") or (data.get("last_serial") if isinstance(data, dict) else None)
    served = int(raw)
    info = data.get("info") if isinstance(data, dict) else None
    releases = data.get("releases") if isinstance(data, dict) else None
    if not isinstance(info, dict) or not isinstance(info.get("name"), str) or not isinstance(releases, dict):
        return served, None, {}
    versions = {}
    for ver, files in releases.items():
        if not isinstance(files, list) or not files:
            continue
        times = [_when(f.get("upload_time_iso_8601")) for f in files if isinstance(f, dict)]
        times = [t for t in times if t is not None]
        if not times:
            continue
        has_sdist = any(isinstance(f, dict) and f.get("packagetype") == "sdist" for f in files)
        versions[ver] = (min(times), has_sdist)
    return served, info["name"], versions


def _new_versions(pkg, versions, serial: int, floor, stage) -> list[NewRelease]:
    """The versions of one changed project to hand the orchestrator, from `_fetch_summary`'s reduced form:
    unseen ones first uploaded at/after the floor (every unseen one when floor is None), and wheel-only ones
    whose sdist has now arrived. `pkg` is None when the project's JSON was malformed: nothing to emit."""
    if pkg is None:
        return []
    out = []
    for ver, (first_upload, has_sdist) in versions.items():
        st = stage(pkg, ver)
        if st is None and (floor is None or first_upload >= floor):
            out.append(NewRelease(pkg, ver, serial))
        elif st in _WHEEL_ONLY and has_sdist:
            out.append(NewRelease(pkg, ver, serial, new_release=False, sdist_upload=True))
    return out


def changes_since(cfg: Config, since_serial: int, *, floor=None, stage=None) -> Changes:
    """Releases in projects whose index serial is above `since_serial`, ascending serial, with `ceiling` set
    (spec: Design 1-4). `floor` (ISO-8601 UTC) bounds which unseen versions count as new; `stage(pkg, ver)` is the
    store's stage lookup, called only on this thread. Never raises: an index failure returns an empty Changes
    with no ceiling, so the cursor holds and the next tick retries."""
    stage = stage or (lambda p, v: None)
    floor = _when(floor)                                # None (backfill, or unparseable) accepts every unseen version
    try:
        meta, changed = _changed(_index_text(cfg), since_serial)
    except Exception as e:
        logger.warning("PyPI simple index unavailable (%s: %s); retrying from serial %d next tick",
                       type(e).__name__, e, since_serial)
        return Changes()
    ceiling = meta
    if len(changed) > cfg.max_projects_per_run:
        ceiling = min(ceiling, changed[cfg.max_projects_per_run][0] - 1)
        changed = changed[:cfg.max_projects_per_run]

    def fetch(item):
        try:
            return _fetch_summary(cfg, item[1])
        except Exception as e:
            return e
    with ThreadPoolExecutor(max_workers=max(1, cfg.fetch_concurrency)) as ex:
        results = list(ex.map(fetch, changed))
    out = []
    for (serial, name), got in zip(changed, results):
        if isinstance(got, RefusedToFetch):
            # Permanently over cfg.max_metadata_bytes: never fetchable, so never let it freeze the cursor.
            logger.error("PyPI JSON for %s refused (%s); skipping it (over the metadata size cap)", name, got)
            continue
        if isinstance(got, Exception):
            logger.warning("PyPI JSON for %s failed (%s: %s); cursor held below serial %d",
                           name, type(got).__name__, got, serial)
            ceiling = min(ceiling, serial - 1)
            continue
        served, pkg, versions = got
        if served is None:
            continue                                    # 404: project gone, nothing new to scan
        if served < serial:                             # a stale CDN copy: re-read it next tick
            ceiling = min(ceiling, serial - 1)
        out.extend(_new_versions(pkg, versions, serial, floor, stage))
    out.sort(key=lambda r: r.serial)
    if len(out) > cfg.max_releases_per_run:
        ceiling = min(ceiling, out[cfg.max_releases_per_run].serial - 1)
        out = out[:cfg.max_releases_per_run]
    res = Changes(out)
    res.ceiling = ceiling
    res.complete = (ceiling == meta)
    return res
