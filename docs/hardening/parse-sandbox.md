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

### Built in: the parse worker

PyDiffWatch runs the parse stage in a sandboxed child process of its own, one per release, on macOS and Linux. It
is on by default (`parse_sandbox = "auto"`); see [GETTING-STARTED.md §9](../../GETTING-STARTED.md#9-state-persistence--containment)
for the three settings.

| Runs in the worker (reads what the package author wrote) | Stays in PyDiffWatch's own process |
|---|---|
| unpacking the sdist (`gzip`, `tarfile`) and reading its PKG-INFO | the PyPI JSON, both sdist downloads, `Requires-Dist` and the dependency lookups |
| the diff (`difflib`) and the execution context (`ast`, `tomllib`, `configparser`, `email.parser`) | the owner history from the database, and the signal line shown to the reviewer |
| the `code` and `binary` rules (`ast.parse`, the rules' regular expressions) | the `dep` and `maintainer` rules, the score, the database, the reviewer and the alerts |

PyDiffWatch sends the worker the two sdists and the rules it has already loaded, on stdin, and gets JSON back.
It checks every field: the types, that each rule id is one it loaded, that each weight is finite and not
negative, and that the reply names the release it asked about. It then recomputes the score and replaces the
dependency and ownership results with its own. So a worker taken over by a malicious archive can at most hide or
invent `code`/`binary` findings. It cannot raise an alert, and it cannot change what PyDiffWatch computed itself.

**macOS (Seatbelt, `sandbox-exec`).** The profile allows everything by default, then denies:
- all network access and all file writes;
- starting any program other than this Python, and forking;
- Mach service lookups, which could ask LaunchServices to open a URL outside the sandbox;
- sending a signal to any other process;
- reading file contents under your home directory, and under the directory PyDiffWatch is imported from, except
  the Python install and the `pydiffwatch/` package itself;
- reading PyDiffWatch's database, cache and lock directories, wherever they are.

File metadata (names, sizes, `stat`) stays readable everywhere. Files outside your home directory that your user
can read (`/etc`, `/tmp` and `$TMPDIR`, `/Users/Shared`, other volumes) stay readable, as they are to any process
of yours.

The worker gets an empty environment and a CPU limit of `parse_timeout_s`, and it is stopped after
`parse_timeout_s` + 10 seconds. The CPU limit stops a parser that runs away; the wall clock is the bound that holds
even for a worker that ignores the CPU limit's signal, as macOS allows. PyDiffWatch reads at most
4 × `max_total_bytes` of the worker's reply, and only the last 500 bytes of its error output. macOS has no
per-process memory limit, so the size caps bound its memory.

**Linux (`systemd-run`).** The worker runs in a transient unit. The unit has:
- `PrivateNetwork=yes`, `ProtectSystem=strict`, `ProtectHome=tmpfs`, `PrivateTmp=yes` and `NoNewPrivileges=yes`;
- `SystemCallFilter=@system-service`;
- `MemoryMax=<parse_memory_max>`, `RuntimeMaxSec=<parse_timeout_s>` and `TasksMax=16`;
- `PrivateUsers=yes` when not running as root.

The Python install and the package are bound read-only, and the database, cache and lock directories are made
inaccessible. The unit inherits none of PyDiffWatch's environment.

**The probe.** Before the first scan of every scanning command (each `run` and `watch` tick, `pending`,
`review-pending` and `capture-evidence`), PyDiffWatch starts the worker once in probe mode. The worker tries to:
- open a network connection;
- write a file next to the database;
- read a file there, and one in your home directory;
- start `/usr/bin/true`;
- look up a macOS service;
- find any of PyDiffWatch's environment values.

The sandbox is used only when every attempt the platform must stop fails (on Linux the unit's limits, not the
child's, bound starting a program, and there is no Mach service to look up). Otherwise `parse_sandbox = "auto"` prints a WARNING and scans
in-process, and `parse_sandbox = "on"` refuses to scan.

The built-in worker narrows what a parser exploit can reach. It does not replace the container, gVisor or
microVM boundary described above, which contains the whole process and is still the stronger choice.

## Verify

The boundary, not just the plumbing, is what matters. A worker that *tries* to reach the network, write the disk
or read your files must fail. PyDiffWatch checks this itself on every run (the probe above). With
`parse_sandbox = "on"`, a check that fails stops the run with `pydiffwatch: parse_sandbox = "on" but …` instead
of scanning. On macOS, the test suite also runs the real sandbox:

```bash
python3 -m pytest -q -m seatbelt tests/test_sandbox.py
```

If you also run PyDiffWatch inside your own container, verify that boundary the same way. Both commands must fail
inside it:

```bash
python -c "import socket; socket.getaddrinfo('pypi.org', 443)"   # no network -> fails
python -c "open('/tmp/x','w')"                                   # read-only filesystem -> fails
```

If either succeeds, the container is not containing the process.
