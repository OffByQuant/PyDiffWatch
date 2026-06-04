# OS-level egress allowlist

The in-code guard (`pydiffwatch/egress.py`) fails closed on any host outside the allowlist, but it lives
*inside* the Python process — an attacker who achieves code-exec in that process can re-import `socket`
and undo it. The **authoritative** default-deny boundary is at the OS, outside the process's authority.
Run PyDiffWatch behind one of the two configurations below; treat the in-code guard as defense-in-depth
and a confused-deputy catch, not as the boundary.

The in-code guard is installed by the **CLI entry point only** (`__main__.main`); it is *not* auto-installed
for library embedders who import the orchestrator, because a library should not monkey-patch the whole
process's socket resolution on its caller's behalf. For any non-CLI use, the OS-level boundary below is the
control that matters — and `run_once()` logs a warning when no in-process guard is installed, so the gap is
visible rather than silent. (A library embedder may also call `egress.install_guard(cfg)` itself, but that
does not replace the OS-level boundary.)

**Allowlist (the only hosts PyDiffWatch needs):**

| Host | Why | Address shape |
|---|---|---|
| `pypi.org` | package JSON + XML-RPC changelog | Fastly CDN — large, changing IP set |
| `files.pythonhosted.org` | sdist downloads | Fastly CDN — large, changing IP set |
| the LLM endpoint | reviewer (`reviewer.base_url`, e.g. a local/LAN model, or `api.anthropic.com` when `reviewer.provider = "anthropic"`) | usually fixed |
| the webhook host | alerts (`webhook_url`, if set) | usually fixed |

The two PyPI hosts sit behind Fastly, so they have no stable IP — which shapes the choice below. If you
run the model locally (`provider = "openai"` pointed at `http://localhost:.../v1`) its host is loopback,
so only the two PyPI hosts (and any webhook) actually leave the machine.

## Option A — domain-aware egress proxy (recommended)

A forward proxy that allowlists by **hostname** is the accurate fit, because two of the four hosts are
CDN-fronted. Run a tiny proxy (e.g. `tinyproxy` with a `Filter`/`Allow` domain list, or `squid` with an
`acl ... dstdomain` whitelist) bound to loopback, force PyDiffWatch through it, and default-deny
everything else at the firewall so nothing can bypass the proxy:

```ini
# /etc/systemd/system/pydiffwatch.service  (drop-in)
[Service]
Environment=HTTPS_PROXY=http://127.0.0.1:8888
Environment=HTTP_PROXY=http://127.0.0.1:8888
# everything except the proxy is denied:
IPAddressDeny=any
IPAddressAllow=localhost
```

```
# tinyproxy.conf — allowlist by domain (default-deny when any Allow/Filter is set)
Port 8888
FilterDefaultDeny Yes
Filter "/etc/tinyproxy/allow.txt"     # lines: pypi.org, files.pythonhosted.org, <llm-host>, <webhook-host>
```

Note: `urllib` honors `HTTPS_PROXY`/`HTTP_PROXY`; the Anthropic SDK honors them too (httpx). The proxy
sees the CONNECT hostname and enforces the domain list; `IPAddressDeny=any` + `IPAddressAllow=localhost`
guarantees no traffic escapes except through it. A loopback LLM endpoint needs no proxy entry — it's
covered by `IPAddressAllow=localhost`.

## Option B — `systemd` IP allowlist (only when every host is fixed-IP)

If you point `pypi_base` at a fixed-IP mirror (or accept maintaining Fastly's CIDRs), `IPAddressAllow=`
is the simplest control — a cgroup-level BPF egress filter, no proxy:

```ini
# /etc/systemd/system/pydiffwatch.service  (drop-in)
[Service]
IPAddressDeny=any
IPAddressAllow=<llm-host-ip>           # the LLM endpoint (omit if it's loopback)
IPAddressAllow=<webhook-ip>            # if webhook_url is set
IPAddressAllow=<mirror-or-fastly-CIDRs>   # PyPI; maintain from https://api.fastly.com/public-ip-list
```

`IPAddressAllow=` takes IPs/CIDRs, not hostnames — that's why Option A is preferred for the standard
Fastly-fronted pypi.org. Refresh Fastly CIDRs on a schedule if you go this route.

### nftables equivalent (non-systemd hosts)

```
table inet pydiffwatch {
  chain out {
    type filter hook output priority 0; policy drop;
    ct state established,related accept
    ip daddr <llm-host-ip> accept            # LLM endpoint (omit if loopback)
    ip daddr @pypi_cidrs accept              # named set, refreshed from Fastly's list (or a mirror)
    # everything else dropped by policy
  }
}
```

## Verify

From inside the unit/namespace, a non-allowlisted connection must be refused:

```bash
# should FAIL (timeout/refused), proving default-deny:
curl -sS https://example.com
# should SUCCEED:
curl -sS https://pypi.org/pypi/pip/json >/dev/null && echo "pypi reachable"
```

If `curl https://example.com` succeeds, egress is NOT contained — the allowlist isn't being enforced at
the OS layer and you're relying only on the in-process guard.
