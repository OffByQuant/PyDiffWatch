# Firehose source: PyPI XML-RPC changelog_since_serial (verify per Task 0; swap source here if blocked).
# xmlrpc.client is defused at the CLI entry point via defusedxml.xmlrpc.monkey_patch() (see __main__.py).
import xmlrpc.client  # nosemgrep: python.lang.security.use-defused-xmlrpc.use-defused-xmlrpc
from .config import Config
from .models import NewRelease

def current_serial(cfg: Config) -> int | None:
    """PyPI's current changelog high-water mark, for 'start monitoring from now' cursor seeding
    (§3.3). Returns None on failure so the caller can skip and retry rather than crawl from genesis."""
    try:
        proxy = xmlrpc.client.ServerProxy(f"{cfg.pypi_base}/pypi")
        return proxy.changelog_last_serial()
    except Exception:
        return None


def changes_since(cfg: Config, since_serial: int) -> list[NewRelease]:
    try:
        proxy = xmlrpc.client.ServerProxy(f"{cfg.pypi_base}/pypi")
        rows = proxy.changelog_since_serial(since_serial)
    except Exception:
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
