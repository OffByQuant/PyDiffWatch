"""Firehose source: PyPI's PEP 691 JSON simple index (`/simple/`: every project and its `_last-serial`), then the
JSON of each project that changed since the cursor. PyPI's XML-RPC changelog is deprecated ("planned for
deprecation", docs.pypi.org/api/) and returned 503 from 2026-09-28; this replaces it. The cursor stays a serial.
A removal no longer arrives as an event: the fetcher's 404 path (fetcher.Removed) catches it, so `removed_at`
stays None."""
import email.message
import gzip
import io
import json
import logging
import re
import urllib.error
import urllib.request

from .config import Config
from .fetcher import read_body

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
    to listed serials."""
    ceiling: int | None = None


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


def changes_since(cfg: Config, since_serial: int, *, floor=None, stage=None) -> Changes:
    return Changes()   # Task 2
