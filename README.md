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

## Install

```bash
git clone <your-fork-url> pydiffwatch && cd pydiffwatch
python3 -m venv .venv && . .venv/bin/activate
pip install -e .                 # core (stdlib + PyYAML)
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

## License

MIT — see [LICENSE](LICENSE).
