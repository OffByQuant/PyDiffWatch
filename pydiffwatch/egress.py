"""Default-deny egress: a process-wide host allowlist enforced at socket.getaddrinfo.

Every outbound connection in PyDiffWatch resolves its hostname through socket.getaddrinfo before it
connects — urllib (PyPI JSON, sdist downloads, webhook), xmlrpc (changelog), and the Anthropic SDK's
httpx all funnel through it, even for IP-literal hosts. Wrapping that single chokepoint lets us fail
CLOSED on any host not on the allowlist, enforcing the architectural invariant that only PyPI, the
configured LLM endpoint, and an optional webhook are ever contacted.

This is defense-in-depth and a confused-deputy guard (e.g. it would catch reviewer.py accidentally
egressing). It is NOT a boundary against an in-process attacker who can re-import socket and undo it —
the authoritative control there is the OS-level allowlist in docs/hardening/egress-allowlist.md. The
guard is installed once at the CLI entry point (__main__.main); it is deliberately NOT auto-installed in
tests (which would mutate global socket state across the suite)."""
import logging
import socket
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

# PyPI's sdist CDN. Download URLs come from the package JSON; for the standard pypi.org this is the host.
# A custom mirror (cfg.pypi_base) that serves files elsewhere must be added to the OS-level allowlist.
_DOWNLOAD_HOST = "files.pythonhosted.org"
_ANTHROPIC_HOST = "api.anthropic.com"

_original_getaddrinfo = None   # the real getaddrinfo captured at install time (None => not installed)


class EgressDenied(Exception):
    """Raised when code attempts to resolve a host outside the configured allowlist (fail-closed)."""


def _host_of(url):
    return urlsplit(url).hostname if url else None


def allowed_hosts(cfg) -> frozenset:
    """The set of hostnames PyDiffWatch may contact, derived from config. Pure.

    Reviewer egress depends on the nested reviewer config: provider="openai" (any OpenAI-compatible
    endpoint, incl. a LAN/local model) contacts cfg.reviewer.base_url; provider="anthropic" contacts
    the Anthropic API."""
    hosts = {_DOWNLOAD_HOST}
    pypi = _host_of(getattr(cfg, "pypi_base", None))
    if pypi:
        hosts.add(pypi)
    if getattr(cfg, "reviewer_enabled", True):
        rc = getattr(cfg, "reviewer", None)
        if rc is not None and rc.provider == "openai":
            h = _host_of(rc.base_url)
            if h:
                hosts.add(h)
        elif rc is not None and rc.provider == "anthropic":
            hosts.add(_ANTHROPIC_HOST)
    wh = _host_of(getattr(cfg, "webhook_url", None))
    if wh:
        hosts.add(wh)
    return frozenset(hosts)


def install_guard(cfg) -> None:
    """Idempotently replace socket.getaddrinfo with an allowlist-enforcing wrapper. Fail-closed."""
    global _original_getaddrinfo
    if _original_getaddrinfo is not None:
        return                                   # already installed — don't double-wrap
    real = socket.getaddrinfo
    allowed = allowed_hosts(cfg)
    logger.info("egress guard installed; allowlist=%s", sorted(allowed))

    def _guarded(host, *args, **kwargs):
        if host is None:                         # local-bind lookup, not egress
            return real(host, *args, **kwargs)
        if host not in allowed:
            raise EgressDenied(f"egress to {host!r} denied (allowlist: {sorted(allowed)})")
        return real(host, *args, **kwargs)

    _original_getaddrinfo = real
    socket.getaddrinfo = _guarded


def uninstall_guard() -> None:
    """Restore the original socket.getaddrinfo (used by tests; no-op if not installed)."""
    global _original_getaddrinfo
    if _original_getaddrinfo is not None:
        socket.getaddrinfo = _original_getaddrinfo
        _original_getaddrinfo = None
