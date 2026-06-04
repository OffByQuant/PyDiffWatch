# PyDiffWatch

A rules-driven supply-chain malware scanner for the PyPI firehose. It polls new package releases,
diffs each against its prior version, runs a **community-extensible rules engine** over the change, and
escalates anything suspicious to an LLM reviewer for a verdict — so a malicious update can be caught and
reported **before** it spreads.

The pipeline, the rules engine, and a starter ruleset are all here and MIT-licensed; you bring your own
compute, your own LLM endpoint, and your own rules.

**New here?** [HOWTO.md](HOWTO.md) is a step-by-step setup-to-deployment guide (endpoints, API keys,
cron/systemd/Docker/CI). This README is the overview.

## The one hard invariant: no execution

PyDiffWatch **never installs, builds, imports, or runs** the packages it analyzes. It downloads the
sdist into memory under strict size caps, reads the source statically (AST + text diff), and discards it.
Analyzed package bytes reach the LLM only as request-body **text**, never as a URL the model fetches.
Community rules are **pure data** (structured YAML) walked by a matcher with no `eval`/`exec` — a
contributed rule can describe matches but can never execute code. This is the property that lets you run
other people's detection rules safely.

## Strongly recommended: run in an isolated environment

The no-execution design above is the primary safeguard — treat it as one layer, not the only one.
PyDiffWatch ingests untrusted bytes from PyPI and evaluates community-authored rules, so run it somewhere a
broken assumption stays contained: a dedicated container, VM, or unprivileged user, with outbound network
restricted to PyPI, your reviewer endpoint, and your webhook. The built-in default-deny egress allowlist
(`pydiffwatch/egress.py`) enforces this in-process, but an OS-level boundary is what holds if the process
itself is compromised. **Do not run it on a workstation or a host with credentials or data you care about.**

See [`docs/hardening/`](docs/hardening/) for concrete recipes — an OS-level egress boundary
([`egress-allowlist.md`](docs/hardening/egress-allowlist.md)) and running the byte-parsing stage under a
container/gVisor or a no-network sandboxed subprocess ([`parse-sandbox.md`](docs/hardening/parse-sandbox.md)).

## Install

```bash
git clone <your-fork-url> pydiffwatch && cd pydiffwatch
python3 -m venv .venv && . .venv/bin/activate
pip install -e .                 # core (stdlib + PyYAML + defusedxml)
pip install -e ".[claude]"       # optional: Anthropic backend
```

Requires Python 3.11+.

## Configure the reviewer (any model, any harness)

The LLM reviewer talks to **any OpenAI-compatible endpoint** or the **Anthropic** API. Copy an example
config and edit it:

```bash
cp examples/ollama.toml pydiffwatch.toml      # or local-qwen / llamacpp / openai / anthropic
```

| Your endpoint | `provider` | `base_url` | API key |
|---|---|---|---|
| llama-swap / vLLM / LM Studio (local) | `openai` | `http://localhost:8000/v1` | none |
| Ollama | `openai` | `http://localhost:11434/v1` | none |
| llama.cpp server | `openai` | `http://localhost:8080/v1` | none |
| OpenAI | `openai` | `https://api.openai.com/v1` | `OPENAI_API_KEY` |
| OpenRouter / Groq / Together | `openai` | the gateway's `/v1` URL | that gateway's key |
| Anthropic | `anthropic` | — (native SDK) | `ANTHROPIC_API_KEY` |

### API keys

**The config holds the env-var NAME; the shell holds the key** — no secret ever lands in a file you might
commit. Wire a hosted endpoint in two steps:

```toml
# pydiffwatch.toml
[reviewer]
provider = "openai"
base_url = "https://api.openai.com/v1"
model = "gpt-4o-mini"
api_key_env = "OPENAI_API_KEY"       # the NAME of the env var — never the key itself
structured_output = "json_schema"
```

```bash
export OPENAI_API_KEY="sk-..."        # in the environment that runs pydiffwatch
```

At request time the key is read from that variable and sent as `Authorization: Bearer <key>`. The name is
yours — point `api_key_env` at `OPENROUTER_API_KEY`, `GROQ_API_KEY`, or anything else, so multiple configs
coexist. **Local endpoints need no key:** omit `api_key_env`. **Anthropic** is the exception — its SDK
reads `ANTHROPIC_API_KEY` from the environment directly, so `api_key_env` is ignored for that provider;
just `export ANTHROPIC_API_KEY=...` and install the extra (`pip install -e ".[claude]"`).

If a model can't produce strict schema-constrained JSON, drop `structured_output` from `json_schema` to
`json_object` (loose JSON) or `none` (prompt-only). The verdict is validated client-side in every mode,
and an invalid one falls back to a heuristic alert rather than being dropped.

→ Per-server recipes and getting the key to your scheduler: **[HOWTO.md](HOWTO.md)**.

## Run

```bash
pydiffwatch -c pydiffwatch.toml seed-now   # set the cursor to PyPI's current serial (start "from now")
pydiffwatch -c pydiffwatch.toml run        # process one tick of new releases (repeat on a schedule)
pydiffwatch -c pydiffwatch.toml pending    # review suspicious releases awaiting your verdict
```

It's a plain CLI over a local SQLite DB (state lives in `.diffwatch/`); nothing is hosted. To monitor
continuously, run `run` on a schedule under **whatever harness you like** — a one-line crontab entry, a
`systemd` timer, a container, or a CI cron job:

```cron
*/15 * * * * cd /opt/pydiffwatch && .venv/bin/pydiffwatch -c pydiffwatch.toml run >> run.log 2>&1
```

→ systemd unit, Dockerfile, and GitHub Actions recipes (with key injection): **[HOWTO.md](HOWTO.md)**.

## Add your own detection rules

Detection lives in `rules/community/*.yaml`. A rule is structured YAML over engine-provided facts — no
code. Example: flag a base64 decode and an exec/eval co-occurring in the same changed file:

```yaml
- id: combo-decode-exec
  applies_to: code
  weight: 45
  attack_type: obfuscated-loader
  match:
    all:
      - bound_call: {category: decode}
      - bound_call: {category: exec}
```

See **[RULES.md](RULES.md)** for the full schema, the predicate reference, and worked examples — written
for both humans and LLM assistants, so you (or your agent) can author a valid rule in a few minutes.

## What's here

PyDiffWatch ships the full pipeline and a baseline ruleset: import-bound primitive detection, auto-exec
location weighting, decode/fetch/credential combos, foreign-language-source, added-dependency reputation,
and maintainer-change signals. The scoring weights and threshold are baselines you can tune. The engine
and rule format here are the ones the community extends.

### Detection scope on brand-new packages

The pipeline's core signal is the **version-to-version diff**, so a package's first-ever release has no
prior version to diff against. `new_package_policy` controls how those are handled:

| Value | First-release behavior |
|---|---|
| `surface` (**default**) | Scan only the files PyPI auto-runs at install/import — `setup.py`, `setup.cfg`, `pyproject.toml`, `__init__.py`, `conftest.py`, `sitecustomize.py`, `.pth` — treating each as fully added. |
| `full` | Scan **every** `.py` file in the new package as added (complete coverage, higher volume/noise). |
| `skip` | Ignore new packages entirely. |

Under the default, malware that lives in a non-auto-exec module of a brand-new package (e.g.
`src/pkg/utils/helper.py`) is **not** scanned — first-release ≠ full scan. Set `new_package_policy = "full"`
if you want complete coverage of first releases and can absorb the extra volume.

## Data attribution

The vendored popularity/typosquat corpus (`pydiffwatch/data/top_pypi_names.txt`, ~5000 names) is a
PEP 503-normalized snapshot derived from [hugovk/top-pypi-packages](https://github.com/hugovk/top-pypi-packages),
which in turn aggregates PyPI download counts from the public BigQuery dataset. It is vendored (not fetched
at runtime); refresh it manually from that source. The upstream repository ships no explicit license — the
file holds package names (facts), not creative content; credit the source if you redistribute it.

## License

MIT — see [LICENSE](LICENSE). Applies to PyDiffWatch's own code, rules, and docs; see **Data attribution**
above for the vendored corpus.
