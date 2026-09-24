# Firehose source: PyPI XML-RPC changelog_since_serial (verify per Task 0; swap source here if blocked).
# Defuse xmlrpc.client against entity-expansion / decompression bombs at IMPORT time, so every importer
# (CLI or library use via the orchestrator) gets a hardened parser before the first ServerProxy call —
# not only __main__. monkey_patch() is global and idempotent.
from defusedxml.xmlrpc import monkey_patch as _defuse_xmlrpc
import xmlrpc.client  # nosemgrep: python.lang.security.use-defused-xmlrpc.use-defused-xmlrpc
_defuse_xmlrpc()
import logging
import urllib.parse

from .config import Config
from .models import NewRelease

logger = logging.getLogger(__name__)


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
    best: dict[tuple[str, str], int] = {}
    for name, version, _ts, action, serial in rows:
        if action != "new release" or version is None:
            continue
        key = (name, version)
        if serial > best.get(key, -1):
            best[key] = serial
    items = [NewRelease(package=n, version=v, serial=s) for (n, v), s in best.items()]
    return sorted(items, key=lambda r: r.serial)
