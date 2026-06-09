# PyDiffWatch

PyDiffWatch polls PyPI for new releases, statically reviews each version-to-version diff for malicious
code embeddings, and alerts before a compromised release spreads. Open-source, MIT.

This file is guidance for AI coding agents (and humans) operating or extending PyDiffWatch on any harness.
For setup and deployment see [GETTING-STARTED.md](GETTING-STARTED.md); for writing detection rules see [RULES.md](RULES.md);
for the project overview see [README.md](README.md).

## The one hard invariant: NO EXECUTION

Analyzed packages are DATA, never code. Never install, build, import, run, `exec`, `eval`, unpickle, or
otherwise execute package content — not to "test" it, not to "confirm" a finding, never. The pipeline only
downloads an sdist into memory (size-capped), extracts it in memory (streamed, never `extractall`, never to
disk), and reads `.py` source with `ast.parse`.

- `reviewer.py` is network-free; `backends.py` is the single sanctioned LLM egress.
- `fetcher.py` performs the only PyPI ingest egress (stdlib `urllib`) and must stay in-memory.
- A URL found *inside* an analyzed package is never fetched.
- API keys: config holds the env-var **name** only, never the literal key.
- `egress.py` installs a process-wide default-deny host allowlist at the CLI entry point.

These are enforced by `tests/test_containment_reviewer.py` (AST guards over reviewer/backends/fetcher).
Keep them green — a failure there is a containment regression, not a flaky test.

## Architecture

Rules engine:
- `facts.py` — `FileFacts` / `DiffFacts` (`build_facts` → `DiffFacts`): per-file import-bound primitive
  categories plus blob / syntax / location facts, and normalized dependency / binary / maintainer facts.
- `rules.py` — YAML loader + **fail-closed validator** + a **pure-data matcher with no eval/exec**
  (`yaml.safe_load` only). This is what makes loading community-authored rules safe.
- `engine.py` — `triage(diff, cfg, ruleset)` scores facts × rules → `TriageResult` / `FiredRule`.
- `rules/community/*.yaml` — the shipped declarative ruleset.

Pipeline: `ingest → fetcher → differ → engine (triage) → reviewer (only when triage escalates) →
notifier → store`, SQLite-backed under `.diffwatch/`. Reviewer config is nested (`cfg.reviewer.*`); see
`config.py` and `examples/`. OS-level hardening guidance (egress boundary, parse sandbox) lives in
`docs/hardening/`.

- `dashboard.py` — static HTML verdict dashboard (PyPI links + report-malware actions); pure render
  functions, no DB/I/O, every untrusted string `html.escape`d. Driven by `orchestrator.export_dashboard`
  / `watch`, exposed as the `dashboard` and `watch` CLI subcommands.

## Detection is declarative

- New detection logic is **general-purpose and rule-based**: heuristics live as YAML rules in
  `rules/community/`, scored by the data-driven engine. Add capability as vetted YAML rules, not as
  hardcoded scoring logic. See [RULES.md](RULES.md).
- The shipped scoring weights and `threshold_t` (default 40) are **baselines** — tune them for your
  tolerance, but keep detection expressed as rules over facts.
- Community rules are **untrusted input**. The no-eval matcher and fail-closed validator in `rules.py` are
  the safety boundary; never weaken them. An invalid rule is dropped at load with a logged warning, never
  executed.

## Working here

- Requires Python 3.11+. Use a virtualenv; run tests with `pytest` (or `python -m pytest`).
- TDD: write the failing test, watch it fail, write the minimal code to make it pass, then commit.
- The reviewer is provider-agnostic: any OpenAI-compatible endpoint (local Qwen / Ollama / llama.cpp /
  vLLM / OpenAI) or the Anthropic SDK, selected by `[reviewer] provider`. Keys come from a named env var.
- Paths (`rules_dir`, `db_path`, `cache_dir`, `lock_path`) default to **cwd-relative**: run from the repo
  root, or set absolute paths in your config for a fixed deployment (cron / systemd / container). If
  `rules_dir` resolves to nothing, the engine loads zero rules and silently never escalates — check it.
