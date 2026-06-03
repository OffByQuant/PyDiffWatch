# PyDiffWatch HOWTO

A step-by-step guide from install to running PyDiffWatch continuously under your own harness. For the
project overview and the no-execution security model, see the [README](README.md); for authoring
detection rules, see [RULES.md](RULES.md).

**Contents**
1. [Install](#1-install)
2. [Choose and wire your LLM endpoint](#2-choose-and-wire-your-llm-endpoint)
3. [API keys](#3-api-keys)
4. [Structured-output modes](#4-structured-output-modes)
5. [The operating loop](#5-the-operating-loop)
6. [Running on a harness](#6-running-on-a-harness-cron--systemd--docker--ci)
7. [State, persistence & containment](#7-state-persistence--containment)
8. [Alerts](#8-alerts)
9. [Heuristic-only mode (no LLM)](#9-heuristic-only-mode-no-llm)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Install

```bash
git clone <your-fork-url> pydiffwatch && cd pydiffwatch
python3 -m venv .venv && . .venv/bin/activate
pip install -e .                 # core: stdlib + PyYAML
pip install -e ".[claude]"       # ONLY if you'll use the Anthropic provider (pulls in the anthropic SDK)
```

Requires Python 3.11+ (the config loader uses the stdlib `tomllib`). Verify the CLI:

```bash
pydiffwatch -c examples/local-qwen.toml --help
```

---

## 2. Choose and wire your LLM endpoint

PyDiffWatch scores every changed release with the rules engine and escalates anything at or above
`threshold_t` to an LLM for a verdict. The reviewer talks to **any OpenAI-compatible endpoint** or the
**Anthropic** API — pick the one matching the model server you run, copy its example to
`pydiffwatch.toml`, and edit `model`/`base_url`.

```bash
cp examples/ollama.toml pydiffwatch.toml      # then edit
```

**Local, OpenAI-compatible, no key** — llama-swap / vLLM / LM Studio
(e.g. `vllm serve Qwen/Qwen2.5-Coder-7B-Instruct --port 8000`) — `examples/local-qwen.toml`:

```toml
[reviewer]
provider = "openai"
base_url = "http://localhost:8000/v1"
model = "qwen-singleshot"            # the model name your server exposes
structured_output = "json_schema"
```

**Ollama** (`ollama serve` exposes `/v1` on 11434; `ollama pull qwen2.5-coder`) — `examples/ollama.toml`:

```toml
[reviewer]
provider = "openai"
base_url = "http://localhost:11434/v1"
model = "qwen2.5-coder"
structured_output = "json_object"    # Ollama json_schema support varies by model; loose JSON is safe
```

**llama.cpp** (`llama-server -m model.gguf --port 8080`) — `examples/llamacpp.toml`:

```toml
[reviewer]
provider = "openai"
base_url = "http://localhost:8080/v1"
model = "local"
structured_output = "json_schema"    # recent GBNF-backed builds; drop to json_object on older ones
```

**OpenAI** — `examples/openai.toml`:

```toml
[reviewer]
provider = "openai"
base_url = "https://api.openai.com/v1"
model = "gpt-4o-mini"
api_key_env = "OPENAI_API_KEY"
structured_output = "json_schema"
```
then `export OPENAI_API_KEY=sk-...` (see §3).

**OpenRouter / Groq / Together / any hosted OpenAI-compatible gateway** — same shape as OpenAI with that
gateway's `base_url` and key variable:

```toml
[reviewer]
provider = "openai"
base_url = "https://openrouter.ai/api/v1"
model = "qwen/qwen-2.5-coder-32b-instruct"
api_key_env = "OPENROUTER_API_KEY"
structured_output = "json_object"
```

**Anthropic** (needs `pip install -e ".[claude]"`) — `examples/anthropic.toml`:

```toml
[reviewer]
provider = "anthropic"
model = "claude-sonnet-4-6"
escalation_model = "claude-opus-4-8"   # optional: escalate low-confidence verdicts to Opus
structured_output = "json_schema"
```
then `export ANTHROPIC_API_KEY=sk-ant-...` (see §3).

---

## 3. API keys

**The rule: the config file holds the env-var NAME; the shell holds the key.** No secret ever lands in a
file you might commit, so any `pydiffwatch.toml` is safe to check in.

For every OpenAI-compatible provider, wire a key in two steps:

1. In `[reviewer]`, set `api_key_env` to the **name** of the variable (not the key):
   ```toml
   api_key_env = "OPENAI_API_KEY"
   ```
2. Export the key in the environment that runs `pydiffwatch`:
   ```bash
   export OPENAI_API_KEY="sk-..."
   ```

At request time PyDiffWatch reads `$OPENAI_API_KEY` and sends `Authorization: Bearer <key>`. The variable
name is yours to choose — use a distinct one per provider so multiple configs coexist (`OPENAI_API_KEY`,
`OPENROUTER_API_KEY`, `GROQ_API_KEY`, …). If `api_key_env` is unset, or the variable is empty, **no auth
header is sent** — which is exactly what a local server wants, so just omit `api_key_env` for
llama-swap / vLLM / Ollama / llama.cpp / LM Studio.

**Anthropic is the exception.** The Anthropic SDK reads `ANTHROPIC_API_KEY` from the environment itself,
so `api_key_env` is **ignored** when `provider = "anthropic"`. Just `export ANTHROPIC_API_KEY=...`. If the
key is missing, that run logs a notice and falls back to heuristic-only — it does not crash.

> Getting the key to your *scheduler* (cron/systemd/Docker/CI), not just your login shell, is the part
> people miss — see §6 for how each harness injects it.

---

## 4. Structured-output modes

`structured_output` controls how strictly the model is made to return machine-readable JSON:

| mode | meaning | use when |
|---|---|---|
| `json_schema` | strict, server-enforced schema | the server supports it (OpenAI, vLLM, recent llama.cpp, Anthropic) — **preferred** |
| `json_object` | "return valid JSON", no schema | Ollama and many gateways |
| `none` | prompt-only; nothing enforces the shape | very small models / last resort |

Regardless of mode, the parsed verdict is **validated client-side** against the review schema. A verdict
missing a required field or carrying an out-of-range enum is rejected, and the release degrades to a
heuristic alert — never a silent pass. Start at `json_schema`; step down only if the logs show
`ReviewUnavailable: non-JSON content`.

---

## 5. The operating loop

**First time only** — set the starting point so you process *new* releases, not all of PyPI history:

```bash
pydiffwatch -c pydiffwatch.toml seed-now
```

(You can skip this: a plain `run` on a fresh database self-seeds the cursor to "now" and processes
nothing that tick, then the next tick polls forward. Use `run --backfill` to process historical releases
from genesis instead.)

**Each tick** — this is what your scheduler runs:

```bash
pydiffwatch -c pydiffwatch.toml run
```

`run` pulls every release since the last cursor (capped by `max_releases_per_run`), diffs each against
its prior version, scores it with the ruleset, and escalates anything ≥ `threshold_t` to the reviewer.
Clear-malicious verdicts alert immediately; borderline "suspicious" ones queue for your judgement.

**Triage the queue:**

```bash
pydiffwatch -c pydiffwatch.toml pending                      # suspicious releases awaiting a verdict, with diffs
pydiffwatch -c pydiffwatch.toml adjudicate <id> malicious --note "curl|sh in setup.py"
pydiffwatch -c pydiffwatch.toml evidence <id>                # print the stored flagged payload for a release
```

`adjudicate` records `benign` | `malicious` | `suspicious`; a non-benign call emits an alert. `evidence`
prints the payload code captured **at detection time** and stored in the DB, so it survives the package
later being pulled from PyPI. To backfill evidence for older flagged rows captured before evidence storage
existed:

```bash
pydiffwatch -c pydiffwatch.toml capture-evidence                 # all reportable rows missing evidence
pydiffwatch -c pydiffwatch.toml capture-evidence --release-id <id>
pydiffwatch -c pydiffwatch.toml capture-evidence --all           # widen to every fired-rule row (more re-fetches)
```

---

## 6. Running on a harness (cron / systemd / Docker / CI)

PyDiffWatch is a plain CLI over a local SQLite DB; "running it" means invoking `run` on a schedule under
whatever runtime you already operate. All four patterns below are equivalent — pick one. Concurrent runs
are safe: a second `run` that overlaps the first sees the lock, prints `run already in progress; exiting`,
and no-ops.

### cron

cron runs with a minimal environment, so inject the key via a small wrapper and use absolute paths. Keep
the key out of the crontab itself.

```bash
# /opt/pydiffwatch/run.sh   (chmod 700)
#!/usr/bin/env bash
set -euo pipefail
cd /opt/pydiffwatch
source ./.env                 # contains: export OPENAI_API_KEY=sk-...   (chmod 600, git-ignored)
exec .venv/bin/pydiffwatch -c pydiffwatch.toml run
```

```cron
*/15 * * * * /opt/pydiffwatch/run.sh >> /opt/pydiffwatch/run.log 2>&1
```

### systemd timer

Better isolation and journald logging. A oneshot service + a timer.

`/etc/systemd/system/pydiffwatch.service`:
```ini
[Unit]
Description=PyDiffWatch one tick

[Service]
Type=oneshot
WorkingDirectory=/opt/pydiffwatch
EnvironmentFile=/opt/pydiffwatch/.env          # KEY=VALUE lines (NO `export`), e.g. OPENAI_API_KEY=sk-...
ExecStart=/opt/pydiffwatch/.venv/bin/pydiffwatch -c pydiffwatch.toml run
```

`/etc/systemd/system/pydiffwatch.timer`:
```ini
[Unit]
Description=Run PyDiffWatch every 15 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=15min
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
systemctl enable --now pydiffwatch.timer
```

> `EnvironmentFile` lines are `KEY=VALUE`, **not** `export KEY=VALUE` (that's the cron wrapper's `.env`).

### Docker

Bind-mount the state directory so the cursor and history persist across container runs.

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install -e .
ENTRYPOINT ["pydiffwatch", "-c", "pydiffwatch.toml"]
```

```bash
docker build -t pydiffwatch .
docker run --rm -v "$PWD/.diffwatch:/app/.diffwatch" -e OPENAI_API_KEY pydiffwatch seed-now
docker run --rm -v "$PWD/.diffwatch:/app/.diffwatch" -e OPENAI_API_KEY pydiffwatch run
```

Schedule the `run` line from the host (cron/systemd calling `docker run`). For a **local** model, point
`base_url` at the host — `http://host.docker.internal:11434/v1` — or share a Docker network with the
model container.

### CI (GitHub Actions cron)

Works, with two caveats: the DB must persist between runs, and there's no local GPU so the reviewer must
be a **hosted** endpoint. Store the key as an Actions secret.

```yaml
on:
  schedule:
    - cron: "*/30 * * * *"
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install -e .
      - uses: actions/cache@v4
        with: { path: .diffwatch, key: pydiffwatch-state }
      - run: pydiffwatch -c pydiffwatch.toml run
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

> The Actions cache is best-effort, not durable storage. For anything you rely on, run PyDiffWatch on a
> host you control and keep `.diffwatch/` on a real volume.

---

## 7. State, persistence & containment

All state lives under `.diffwatch/` (paths configurable via `db_path`, `cache_dir`, `lock_path`):

- `diffwatch.sqlite` — the cursor, every processed release, verdicts, alerts, and stored payload evidence.
- `artifact_cache/` — downloaded sdists (size-capped, read in memory, never installed).
- `diffwatch.lock` — an exclusive `flock` that prevents overlapping `run`s.

Persist `.diffwatch/` and you can move PyDiffWatch between machines without losing the cursor or history.
The download/extraction caps (`max_download_bytes`, `max_member_bytes`, `max_total_bytes`,
`max_decompressed_bytes`, …) bound how much of any sdist is ever read into memory; the package is never
installed, built, imported, or executed — see the [README invariant](README.md#the-one-hard-invariant-no-execution).

**Hardening (defense-in-depth).** PyDiffWatch installs a process-wide default-deny egress allowlist
(`pydiffwatch/egress.py`) so it can only contact PyPI, the configured reviewer endpoint, and an optional
webhook. For production deployments, two guides under [`docs/hardening/`](docs/hardening/) cover the
authoritative OS-level boundaries: [`egress-allowlist.md`](docs/hardening/egress-allowlist.md) (domain-aware
proxy / `systemd` IP allowlist / `nftables`) and [`parse-sandbox.md`](docs/hardening/parse-sandbox.md)
(running the byte-parsing stage under a container/gVisor or a no-network sandboxed subprocess).

---

## 8. Alerts

Set `webhook_url` (top-level, not under `[reviewer]`) to receive each new alert as a JSON POST —
`{"text": "..."}`, Slack-incoming-webhook compatible:

```toml
webhook_url = "https://hooks.slack.com/services/XXX/YYY/ZZZ"
```

Alerts are also printed to stdout and recorded (deduped) in the DB, so a webhook failure never loses one.

---

## 9. Heuristic-only mode (no LLM)

To run with no model at all — rules and weights only, no endpoint required — set:

```toml
reviewer_enabled = false
```

Every release crossing `threshold_t` becomes a heuristic alert. Useful for a first pass on a box with no
GPU and no API budget, or to keep monitoring when your endpoint is down.

---

## 10. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `ReviewUnavailable: non-JSON content` in logs | the model isn't honoring the JSON contract. Lower `structured_output` (`json_schema` → `json_object` → `none`) or use a more capable model. The release still alerted heuristically — nothing was dropped. |
| Every Anthropic run logs `heuristic-only this run` | `ANTHROPIC_API_KEY` isn't in the environment the *scheduler* uses. Put it in the systemd `EnvironmentFile` / cron wrapper / Actions secret, not just your interactive shell. |
| `401`/`403` from a hosted endpoint | `api_key_env` names a variable that's unset, empty, or wrong. Check it from the harness's environment: `echo $OPENAI_API_KEY`. |
| First `run` returns `processed 0 releases` | expected — a fresh DB seeds the cursor to "now" and processes nothing that tick; the next tick polls forward. Use `run --backfill` to process history instead. |
| `run already in progress; exiting` | a previous tick still holds the lock. Harmless; space your schedule so a tick finishes before the next fires. |
| Local endpoint refused / connection error | the model server isn't up, or `base_url` is wrong (check the port and the trailing `/v1`). From Docker, use `host.docker.internal`, not `localhost`. |
