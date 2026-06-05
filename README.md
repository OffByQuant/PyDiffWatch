# 🛡️ PyDiffWatch

**Catch malicious PyPI updates before they spread — with a cheap local model and rules anyone can write.**

> 🌐 **A community early-warning system for the PyPI supply chain.** The more people watching the release
> firehose, the sooner a compromised package gets caught — and reported for takedown. Cheap to run, simple
> to extend, and you don't need to be a security expert to help.

Supply-chain attacks on open-source packages are escalating: an attacker ships a compromised version of a
trusted package, and it's pulled into thousands of installs before anyone notices. Defending against that
shouldn't require a security budget or a SaaS subscription. PyDiffWatch is an open-source (MIT) scanner
that watches the PyPI release firehose, statically reviews what changed in each new version, and alerts
you **before** a malicious update spreads — running on hardware you already have.

It's built for the community to **extend** and to **afford**: the per-release review runs on a **local,
open-source LLM** (no per-token bill), and detection logic is **plain YAML rules** anyone can contribute.

---

## ⚙️ How it works

```
new PyPI releases → diff against the prior version → community rules score the change
   → anything suspicious goes to a local LLM reviewer → you get alerted
```

State lives in a local SQLite database; nothing is hosted, and nothing leaves your machine except the
calls to PyPI and the model endpoint you point it at.

---

## 💡 Why PyDiffWatch

- **Cheap by design.** The reviewer is meant to run on a local open-source model — the only setup it has
  been tested against — so watching the whole firehose costs you compute, not API credits. Hosted and
  frontier APIs (OpenAI, Anthropic, OpenRouter, DeepSeek, …) work too, but local keeps it free.
- **It never runs what it inspects.** Analyzed packages are *data, never code*: PyDiffWatch downloads an
  sdist into memory, reads the source statically, and discards it — no install, build, import, or `exec`.
  Package bytes reach the model only as request-body text, never as a URL it fetches. [More ↓](#-run-it-safely)
- **Community rules, run safely.** Detection rules are pure structured data (YAML) evaluated by a matcher
  with no `eval`/`exec` — so you can run other people's rules without running their code. See [RULES.md](RULES.md).

---

## 🚀 Get started — the easy way

Clone it, open your favorite agent harness (**Claude Code**, **opencode**, or similar), and give it one prompt:

> *"Install the dependencies and let's configure the API endpoint to use a local model and start polling."*

The agent handles setup and drives the polling loop; your local model does the reviews. That's the
two-tier idea in a nutshell — a frontier model can **orchestrate** while a cheap local model does the
**per-release review work**.

---

## 🛠️ Get started — by hand

No agent required. Plain commands poll the firehose and still use your local LLM for every review:

```bash
git clone https://github.com/OffByQuant/PyDiffWatch pydiffwatch && cd pydiffwatch
python3 -m venv .venv && . .venv/bin/activate
pip install -e .                                # requires Python 3.11+

cp examples/local-qwen.toml pydiffwatch.toml    # point at your local model endpoint
pydiffwatch -c pydiffwatch.toml seed-now        # start watching "from now"
pydiffwatch -c pydiffwatch.toml run             # process new releases (repeat on a schedule)
pydiffwatch -c pydiffwatch.toml pending         # see suspicious releases awaiting your verdict
```

Drop `run` into a cron job, `systemd` timer, container, or CI schedule to monitor continuously. You can
also run with **no model at all** (rules-only heuristic alerts) when you have no GPU or budget.

**→ Full setup — endpoints, API keys, scheduling, heuristic-only mode, troubleshooting:
[GETTING-STARTED.md](GETTING-STARTED.md)**

---

## 🗄️ What it records

Everything lives in a single local SQLite database under `.diffwatch/` — nothing is hosted. It keeps a
**cursor** (how far through PyPI's serial stream you've scanned), one **releases** row per version it
processed (the diff basis, the triage score, and which rules fired), an **alerts** row per notification
sent, and a **verdicts** row with the reviewer's call — classification, confidence, attack type, reasoning,
and model — plus your own `human_label` once you adjudicate it with `pending`.

A `releases` × `verdicts` slice from a real run (triage score is an unbounded sum of fired-rule weights;
the default escalation threshold is 40, so anything below it never reaches the reviewer):

```text
package  version  triage_score  attack_type       classification
-------  -------  ------------  ----------------  --------------
pkg-a    9.1.0          21135   install-hook-rce  malicious
pkg-b    2.9.32         16400   typosquat         malicious
pkg-c    0.7.2           5975   dropper           malicious
pkg-d    1.0.44          2510   typosquat         suspicious
pkg-e    3.13.0        167740   none              benign
```

*(Package names anonymized.)* The last row is why the LLM reviewer earns its place: a brand-new package can
rack up a huge heuristic score yet be correctly cleared as benign on inspection — catching the false
positive before it ever becomes an alert.

---

## 🔒 Run it safely

PyDiffWatch ingests untrusted bytes from PyPI and runs community-authored rules. The no-execution design
is the primary safeguard, but treat it as one layer: run it in a container, VM, or unprivileged user with
outbound network restricted to PyPI, your model endpoint, and your webhook — **not on a workstation that
holds credentials or data you care about.** A built-in default-deny egress allowlist enforces this
in-process; an OS-level boundary is what holds if the process itself is ever compromised.

→ Concrete isolation recipes: [`docs/hardening/`](docs/hardening/).

---

## 🧩 Bring your own rules

PyDiffWatch ships a **basic starter set** of detection rules — enough to get you catching the obvious
attacks out of the box, not the last word. The rules live as plain YAML in the [`rules/community/`](rules/community)
folder, and the whole point is that **you extend them with your own**: structured YAML over
engine-provided facts, no code. If you can describe an attack pattern (say, "a base64 decode and an
`exec` in the same changed file"), you can add a rule in a few minutes — drop another `.yaml` file in
that folder and it's picked up automatically.

[RULES.md](RULES.md) has the schema, the predicate reference, and worked examples — written for humans and
LLM assistants alike, so you (or your agent) can author and contribute one quickly.

---

## 🤝 Contributing & community

PyDiffWatch gets stronger with scale: more people watching the firehose means malicious releases are
spotted sooner, and more shared rules means more attack patterns caught. You don't need to be a security
researcher or own a GPU to help.

- **Watch, and report what you catch.** Run it, and when a flagged release is genuinely malicious, report
  it to PyPI for takedown. Every extra watcher shortens the window an attacker has.
- **Write a rule.** If you can describe an attack pattern, you can add a YAML rule and open a pull request —
  [RULES.md](RULES.md) walks you through it. No code, no `eval`.
- **Share a config or a fix.** Better example configs, clearer docs, and bug fixes are all welcome.

If you can clone a repo and edit a YAML file, you can contribute. That's the whole point.

---

## 🗺️ Roadmap

Directions, not promises — contributions toward any of these are welcome:

- **Built-distribution review.** Inspect wheels (`bdist`), not just sdists, so attacks shipped only in the
  built artifact don't slip past.
- **More alert destinations.** Additional notifier backends beyond the current webhook (e.g. email, chat).
- **A shared rule index.** Make it easy to discover, pull, and combine rule packs others have written.
- **A labeled evaluation set.** Measure detection precision/recall against known-malicious historical
  releases, so rule and weight changes can be scored instead of guessed.
- **Easier install.** A published package / `pipx` one-liner instead of an editable clone.
- **Resilient long runs.** Rate-limit-aware, resumable polling for unattended deployments.

---

## 🤖 Built with AI

PyDiffWatch was developed with heavy use of AI coding agents (Claude Code) alongside the same kind of
local open-source models it runs on. The parts that matter most — the no-execution boundary, the
no-`eval` rule matcher, the egress allowlist — are human-reviewed and locked down by the containment test
suite, so AI assistance never gets to quietly weaken a security invariant.

---

## 📄 License & attribution

MIT — see [LICENSE](LICENSE); applies to PyDiffWatch's own code, rules, and docs. The vendored
popularity/typosquat corpus (`pydiffwatch/data/top_pypi_names.txt`, ~5000 names) is a PEP 503-normalized
snapshot derived from [hugovk/top-pypi-packages](https://github.com/hugovk/top-pypi-packages) (aggregated
from PyPI's public BigQuery download stats); it's vendored, not fetched at runtime. The upstream ships no
explicit license — the file holds package names (facts), not creative content; credit the source if you
redistribute it.
