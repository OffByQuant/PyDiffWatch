import socket
import pytest
from pydiffwatch.config import Config, ReviewerConfig
from pydiffwatch import egress


@pytest.fixture(autouse=True)
def _restore_guard():
    # Every test here mutates the process-wide socket.getaddrinfo; always restore so a failure
    # mid-test can't leak the guard into the rest of the suite.
    yield
    egress.uninstall_guard()


# ---- allowed_hosts (pure) ----

def test_allowed_hosts_openai_backend_includes_endpoint_excludes_anthropic():
    cfg = Config(reviewer=ReviewerConfig(provider="openai", base_url="http://192.168.0.5:8000/v1"))
    hosts = egress.allowed_hosts(cfg)
    assert "files.pythonhosted.org" in hosts
    assert "pypi.org" in hosts                 # from default cfg.pypi_base
    assert "192.168.0.5" in hosts              # the configured OpenAI-compatible endpoint
    assert "api.anthropic.com" not in hosts


def test_allowed_hosts_anthropic_backend_includes_anthropic():
    cfg = Config(reviewer=ReviewerConfig(provider="anthropic"))
    hosts = egress.allowed_hosts(cfg)
    assert "api.anthropic.com" in hosts
    assert "localhost" not in hosts            # the openai base_url is not consulted for anthropic


def test_allowed_hosts_includes_webhook_when_set():
    cfg = Config(webhook_url="https://hooks.example.com/services/abc")
    assert "hooks.example.com" in egress.allowed_hosts(cfg)


def test_allowed_hosts_omits_reviewer_when_disabled():
    cfg = Config(reviewer_enabled=False,
                 reviewer=ReviewerConfig(provider="openai", base_url="http://10.0.0.9:8000/v1"))
    hosts = egress.allowed_hosts(cfg)
    assert "10.0.0.9" not in hosts and "api.anthropic.com" not in hosts
    assert "pypi.org" in hosts and "files.pythonhosted.org" in hosts   # ingest/fetch hosts still allowed


def test_allowed_hosts_custom_pypi_mirror():
    cfg = Config(pypi_base="https://mirror.internal.corp")
    assert "mirror.internal.corp" in egress.allowed_hosts(cfg)


# ---- assert_web_scheme (the file:// guard the host allowlist can't catch) ----

@pytest.mark.parametrize("url", ["https://pypi.org/x", "http://localhost:8000/v1"])
def test_assert_web_scheme_allows_http_https(url):
    egress.assert_web_scheme(url)   # must not raise


@pytest.mark.parametrize("url", [
    "file:///etc/passwd", "ftp://host/x", "data:text/plain,hi", "", None, "/etc/passwd",
])
def test_assert_web_scheme_rejects_non_web(url):
    with pytest.raises(egress.EgressDenied):
        egress.assert_web_scheme(url)


# ---- install_guard / uninstall_guard ----

def test_guard_allows_listed_host_and_blocks_others():
    cfg = Config(reviewer=ReviewerConfig(provider="openai", base_url="http://192.168.0.5:8000/v1"))
    calls = []
    socket.getaddrinfo = lambda host, *a, **k: calls.append(host) or "SENTINEL"   # the "real" resolver
    egress.install_guard(cfg)

    assert socket.getaddrinfo("pypi.org", 443) == "SENTINEL"          # allowed -> delegates
    assert socket.getaddrinfo("192.168.0.5", 8000) == "SENTINEL"      # configured endpoint -> delegates
    assert calls == ["pypi.org", "192.168.0.5"]
    with pytest.raises(egress.EgressDenied):
        socket.getaddrinfo("evil.example.com", 443)                   # off-list -> fail closed


def test_guard_passes_none_host_through():
    # A None host is a local-bind lookup, not egress; it must delegate, not raise.
    cfg = Config()
    sentinel = object()
    socket.getaddrinfo = lambda host, *a, **k: sentinel
    egress.install_guard(cfg)
    assert socket.getaddrinfo(None, 0) is sentinel


def test_uninstall_restores_original():
    cfg = Config()
    original = socket.getaddrinfo
    egress.install_guard(cfg)
    assert socket.getaddrinfo is not original
    egress.uninstall_guard()
    assert socket.getaddrinfo is original


def test_install_is_idempotent():
    cfg = Config()
    real = lambda host, *a, **k: "REAL"
    socket.getaddrinfo = real
    egress.install_guard(cfg)
    wrapped_once = socket.getaddrinfo
    egress.install_guard(cfg)                       # second install must be a no-op (no double-wrap)
    assert socket.getaddrinfo is wrapped_once
    assert socket.getaddrinfo("pypi.org", 443) == "REAL"   # still delegates to the original real resolver
