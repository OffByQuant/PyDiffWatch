# Firehose source: PyPI XML-RPC changelog_since_serial (verify per Task 0; swap source here if blocked).
# Defuse xmlrpc.client against entity-expansion / decompression bombs at IMPORT time, so every importer
# (CLI or library use via the orchestrator) gets a hardened parser before the first ServerProxy call —
# not only __main__. monkey_patch() is global and idempotent.
from defusedxml.xmlrpc import monkey_patch as _defuse_xmlrpc
import xmlrpc.client  # nosemgrep: python.lang.security.use-defused-xmlrpc.use-defused-xmlrpc
_defuse_xmlrpc()
import datetime
import logging
import urllib.parse

from .config import Config
from .models import NewRelease

logger = logging.getLogger(__name__)

# The changelog action logged when a release's sdist is uploaded; Warehouse logs `add <python_version> file
# <filename>`, and an sdist's python_version is "source". `new release` fires on a release's FIRST file, so when
# the wheels upload first the release waits in no_sdist_wait (or, once decided, is no_sdist); this later event
# re-scans it at once (spec U4).
# LIVE-RUN VERIFY: the exact string is unverified offline. Check a live changelog_since_serial batch.
SDIST_UPLOAD_ACTION = "add source file "


def _proxy(cfg: Config):
    """An XML-RPC proxy whose socket reads time out after fetch_timeout_s; without one, a hung call stalls
    the scan tick forever."""
    base = xmlrpc.client.SafeTransport if urllib.parse.urlsplit(cfg.pypi_base).scheme == "https" \
        else xmlrpc.client.Transport

    class _Timeout(base):
        timeout = cfg.fetch_timeout_s

        def make_connection(self, host):
            conn = super().make_connection(host)
            conn.timeout = self.timeout
            return conn
    return xmlrpc.client.ServerProxy(f"{cfg.pypi_base}/pypi", transport=_Timeout())

def current_serial(cfg: Config) -> int | None:
    """PyPI's current changelog high-water mark, for 'start monitoring from now' cursor seeding
    (§3.3). Returns None on failure so the caller can skip and retry rather than crawl from genesis."""
    try:
        return _proxy(cfg).changelog_last_serial()
    except Exception:
        return None


def changes_since(cfg: Config, since_serial: int) -> list[NewRelease]:
    try:
        rows = _proxy(cfg).changelog_since_serial(since_serial)
    except Exception as e:
        logger.warning("PyPI changelog request failed (%s: %s); retrying from serial %d next tick",
                       type(e).__name__, e, since_serial)
        return []  # next tick retries from the same serial — no gap
    best: dict[tuple[str, str], list] = {}   # (name, version) -> [serial, new release seen, sdist upload seen]
    removed: dict[tuple[str, str], tuple] = {}   # (name, version) -> (serial, time) of a same-batch `remove release`
    last: dict[tuple[str, str], int] = {}         # (name, version) -> its latest new-release/upload serial
    for name, version, ts, action, serial in rows:
        if action == "remove release" and version is not None:
            if isinstance(ts, (int, float)) and not isinstance(ts, bool):
                try:
                    removed[(name, version)] = (serial, datetime.datetime.fromtimestamp(ts, datetime.UTC).isoformat())
                except (OverflowError, ValueError, OSError):
                    pass                    # unrepresentable: no evidence, so the release waits one re-check
            continue
        sdist = action.startswith(SDIST_UPLOAD_ACTION)
        if (action != "new release" and not sdist) or version is None:
            continue
        ev = best.setdefault((name, version), [serial, False, False])
        last[(name, version)] = max(last.get((name, version), serial), serial)
        # The FIRST serial: the cursor never passes an event of an item not yet processed, even when the
        # per-run cap cuts the list (a later event of the item is re-seen next tick, a cheap no-op).
        ev[0] = min(ev[0], serial)
        ev[1 if not sdist else 2] = True
    items = [NewRelease(package=n, version=v, serial=s, new_release=nr, sdist_upload=sd,
                        removed_at=removed[(n, v)][1] if (n, v) in removed and removed[(n, v)][0] > last[(n, v)]
                        else None)   # a removal evidences only when no re-upload followed it
             for (n, v), (s, nr, sd) in best.items()]
    return sorted(items, key=lambda r: r.serial)
