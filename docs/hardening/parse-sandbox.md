# Isolating the extract + parse stage

PyDiffWatch never executes, installs, imports, or builds the packages it analyzes — it downloads an
sdist into memory, extracts it through hard byte/member ceilings, and reads the Python source with
`ast.parse`. That static-only design already removes essentially all of the supply-chain attack surface:
there is no install hook, no `setup.py` run, no import of package code, nothing that gives attacker code
a thread of execution.

What remains is a narrow, theoretical path: a **memory-corruption CVE in a parser that touches
attacker-controlled bytes**. In PyDiffWatch that means exactly two libraries:

- `gzip` + `tarfile` — `fetcher.extract_sdist` decompresses and walks the archive (streamed, never
  `extractall`, bounded by `max_decompressed_bytes` / `max_member_bytes` / `max_total_bytes`).
- `ast.parse` (CPython's tokenizer/parser) — the triage stage parses extracted `.py` source.

A malformed archive or source file that triggered a bug in one of these *could*, in principle, turn
byte-reading into code-execution inside the PyDiffWatch process. The byte ceilings make a resource bomb
(zip/decompression/name bomb) the realistic case and already contain it; a true parser RCE is
lower-likelihood still. But it is the one residual path that process-internal controls can't fully close,
because the vulnerable code is the parser itself.

## The control: contain the parser, not the whole program

The fix is to run **only the extract + parse stage** in a throwaway sandbox that has **no network and no
writable filesystem**, so even a parser RCE lands in a box that can neither exfiltrate nor persist. Pair
it with the egress allowlist (`egress-allowlist.md`): egress denies the network at the host, the parse
sandbox denies it (and the disk) at the stage that actually touches hostile bytes.

The networked half (resolve version, download blobs from PyPI) stays in the parent — it needs the network
by definition and parses no attacker bytes beyond the size-bounded download loop. Only the in-memory
blobs cross into the sandbox, which returns a structured diff + triage result back over a pipe.

### Recommended for "any harness": an OS/container boundary

PyDiffWatch is built to run anywhere — cron, a container, CI, a laptop — so the portable, strongest
containment story is to **run the whole process inside a locked-down container or microVM** and let that
be the boundary:

- **gVisor** (`runsc`) — a user-space kernel that intercepts syscalls; a parser RCE never reaches the
  host kernel. The best fit when you want strong isolation without a VM.
- **A minimal container** with `--network none` for an offline re-analysis pass, a read-only root
  filesystem (`--read-only`), dropped capabilities (`--cap-drop=ALL`), and a `seccomp` profile.
- **A microVM** (Firecracker / Kata) when you want a hardware-virtualization boundary.

This needs no code change in PyDiffWatch — it's deployment configuration — and it contains the entire
pipeline, not just the parser. For most operators this is the right amount of hardening.

### Optional: a per-stage sandboxed subprocess (contributor pattern)

When you can't wrap the whole process (e.g. PyDiffWatch shares a host with other work), you can isolate
*just* the parse stage in a sandboxed child. On Linux with systemd this is a small, dependency-free
pattern using `systemd-run`:

```
systemd-run --pipe --wait --collect --quiet \
  --property=PrivateNetwork=yes          `# no egress from the parse stage` \
  --property=ProtectSystem=strict        `# entire filesystem read-only` \
  --property=ProtectHome=read-only       `# tighten to tmpfs if your code lives outside /home` \
  --property=SystemCallFilter=@system-service  `# seccomp allowlist` \
  --property=MemoryMax=512M \
  --property=RuntimeMaxSec=30 \
  --property=TasksMax=16 \
  -- python -m pydiffwatch._parse_worker
```

The shape, if someone wants to contribute it:

1. **Split `fetcher.fetch_artifacts`** into a networked half (`resolve_and_download` → the two sdist
   blobs + maintainer metadata + dep findings) and a pure half (`extract → build_diff → triage`). The
   pure half is the single source of truth, called both by the worker and by an in-process fallback.
2. **A worker entry point** (`python -m pydiffwatch._parse_worker`) that reads `{cfg, bundle}` JSON from
   stdin, runs the pure half, and writes `{diff, triage}` JSON to stdout. It imports no package code,
   opens no socket, touches no sqlite. Blobs cross the pipe base64-encoded.
3. **A dispatch** (`run_extract_parse(cfg, bundle)`) that runs the worker under `systemd-run` when
   available and falls back to the pure function in-process otherwise (macOS/dev, or where `systemd-run`
   is absent) — so the sandbox degrades cleanly and the pipeline still runs everywhere.
4. **Map a worker crash/timeout** to a retryable, non-terminal stage (mirror the existing
   `fetch_failed` handling) so a sandbox failure never poisons the tick or silently drops a release.

Keep the LLM reviewer call in the **parent**, not the worker — the reviewer needs egress to the model
endpoint, which the sandbox forbids by design, and the reviewer already handles only structured diff text
(never raw archive bytes).

`systemd-run` is Linux/systemd-specific; that is why the container/gVisor route above is the recommended
default for a tool meant to run on any harness. The per-stage subprocess is the right call when you need
isolation *without* containerizing the whole process — otherwise prefer the OS boundary.

## Verify

The boundary, not just the plumbing, is what matters — a worker that *tries* to reach the network or write
the disk must fail inside the sandbox:

```bash
# inside the sandbox, both must fail:
python -c "import socket; socket.getaddrinfo('pypi.org', 443)"   # PrivateNetwork -> fails
python -c "open('/tmp/x','w')"                                   # ProtectSystem=strict -> read-only fs
```

If either succeeds, the stage is not contained — the parser is still running with host network/disk
authority.
