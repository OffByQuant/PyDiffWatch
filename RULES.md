# Writing PyDiffWatch Rules

PyDiffWatch detection rules are **structured YAML** placed in `rules/community/*.yaml`. They are pure
data: the engine walks them against facts it computed from a package diff. **There is no code in a rule
and no `eval` in the matcher** — a rule can describe a match but can never execute. A rule that fails
validation (unknown predicate, wrong-scope predicate, bad value, malformed tree) is dropped at load time
with a logged warning and never evaluated. This is what makes it safe to load rules from anyone.

This guide is written so a human *or* an LLM assistant can author a valid rule. If you're an assistant:
emit YAML that conforms exactly to the schema below; do not invent predicates or fields.

## How scoring works

For each changed release the engine builds **facts**, runs every rule whose `match` is satisfied, and
**sums the weights** of the fired rules. If the total reaches the configured threshold (`threshold_t`,
default 40), the release is escalated to the LLM reviewer. Weights are additive and tunable — there is no
magic; a rule worth 45 on its own crosses the default threshold, a rule worth 20 needs a second signal.

## Rule fields

| field | required | meaning |
|---|---|---|
| `id` | yes | unique identifier (kebab-case) |
| `applies_to` | yes | evaluation scope: `code` \| `binary` \| `dep` \| `maintainer` |
| `weight` | yes | points added when the rule fires (number) |
| `match` | yes | a boolean tree of predicates (below) |
| `attack_type` | no | informational label (e.g. `credential-exfil`) |
| `location_scaled` | no | if `true`, the fired weight is multiplied by the file's location weight (code scope only); default `false` |
| `description` | no | human/LLM-readable explanation |

**Evaluation scope** decides what each rule runs against:
- `code` — evaluated once per changed `.py`/`.pyx`/`.pyi` file.
- `binary` — once per added non-source / oversized / foreign member.
- `dep` — once per newly-added dependency finding.
- `maintainer` — once per release.

Rules in `binary`/`dep` scope fire **once per matching item**, and the weights sum — so two foreign-language
files at weight 25 contribute 50 automatically.

## The `match` tree

`match` is a single node. A node is either a **boolean** node or a **predicate** leaf.

- `all: [ ...nodes... ]` — true if every child is true (AND)
- `any: [ ...nodes... ]` — true if any child is true (OR)
- `not: { ...node... }` — negation

Predicate leaves (each a one-key mapping). The **Scope** column says which `applies_to` it's valid in;
using a predicate outside its scope makes the rule invalid (and dropped).

| predicate | scope | fires when |
|---|---|---|
| `bound_call: {category: <c>}` | code | an import-bound call of category `c` is on an added line. `c ∈ decode, exec, process, network, credential`. Accepts a list: `{category: [decode, exec]}` (any of). |
| `bound_call: {name: <fn>}` | code | a bound/builtin call with that exact function name (e.g. `system`, `b64decode`) is on an added line |
| `import_present: {module: <m>}` | code | module `m` is imported in the file |
| `regex: {pattern: <re>}` | code | any added line matches the regular expression |
| `blob_present: true` | code | the file has an added line that looks like an encoded blob (long base64 run, very long line, or high-entropy window) |
| `syntax_error: true` | code | a complete `.py` file fails to parse |
| `location_at_least: <n>` | code | the file's location weight ≥ `n` (3.0 = auto-exec/auto-import: `setup.py`/`setup.cfg`/`pyproject.toml`/`__init__.py`/`conftest.py`/`sitecustomize.py`/`.pth`; 1.0 = normal; 0.2 = tests/docs/examples) |
| `binary_reason: <r>` | binary | the binary's reason is `r`. `r ∈ source-too-large, foreign-language-source, new-binary` |
| `dep_reason: <r>` | dep | the dependency finding's reason is `r`. `r ∈ typosquat, nonexistent, brand-new` |
| `maintainer_changed: true` | maintainer | the owner set changed vs. the prior stored release |

### What "import-bound" means (and why it matters)

`bound_call` only counts a call when its receiver resolves, through the file's imports, to a dangerous
origin. `os.system(...)` counts as `process`; `re.compile(...)` does **not** count as `exec`;
`pickle.loads(...)` counts as `decode` but `json.loads(...)` does not. This binding is what keeps rules
precise — you can write `bound_call: {category: exec}` without it firing on every `.compile()` in the
ecosystem.

## Worked examples

**1. Download-and-run in an install hook (high confidence, escalates alone):**
```yaml
- id: autoexec-location
  applies_to: code
  weight: 45
  attack_type: install-hook
  match:
    all:
      - location_at_least: 3.0
      - any:
          - bound_call: {category: process}
          - bound_call: {category: exec}
          - bound_call: {category: network}
```

**2. Credentials read and sent out (exfil):**
```yaml
- id: combo-cred-network
  applies_to: code
  weight: 45
  attack_type: credential-exfil
  match:
    all:
      - bound_call: {category: credential}
      - bound_call: {category: network}
```

**3. A specific dangerous call by name, anywhere in changed code (accumulating signal):**
```yaml
- id: marshal-loads-used
  applies_to: code
  weight: 20
  description: marshal.loads on added lines — deserializing opaque bytecode is a loader smell.
  match:
    bound_call: {name: loads}
```

**4. A newly-added typosquat dependency (escalates alone):**
```yaml
- id: dep-typosquat
  applies_to: dep
  weight: 40
  attack_type: dependency-typosquat
  match:
    dep_reason: typosquat
```

## Testing your rule

Drop the YAML in `rules/community/`, then check it loads and behaves:

```python
from pathlib import Path
from pydiffwatch.rules import load_rules
from pydiffwatch.engine import triage
from pydiffwatch.config import Config
from pydiffwatch.models import Diff, FileDiff, Hunk

rules = load_rules(Path("rules/community"))
assert any(r.id == "your-rule-id" for r in rules)   # if absent, it failed validation (check the logs)

def code(path, lines):
    return Diff("p", "1.1", False, [FileDiff(path, "modified",
        [Hunk((0, 0), (0, len(lines)), lines, [])], "\n".join(lines))], [])

res = triage(code("setup.py", ["import os", "os.system('id')"]), Config(), rules)
print(res.score, res.escalate, [fr.rule for fr in res.fired_rules])
```

If your rule doesn't appear in `load_rules(...)`, it was rejected as invalid — run with logging at
`WARNING` to see why.

## Safety notes

- Rules are **pure data** — the loader uses `yaml.safe_load` and the matcher never calls
  `eval`/`exec`/`getattr`. A rule can describe a match; it cannot run code. An invalid rule is dropped at
  load (fail-closed), so one bad rule can never break the rest of the ruleset.
- The `regex` predicate runs your pattern against **untrusted package text** at match time, using
  Python's backtracking `re` engine. A pathologically nested pattern (e.g. `(a+)+$`) can backtrack
  catastrophically and hang. Patterns are length-capped (1000 chars) to bound the surface, but the cap
  does not prevent catastrophic backtracking. **Prefer `bound_call` and the other structural predicates
  over `regex`**, and keep any regex simple and anchored.

## Design intent

Rules describe **observable signals**, not conclusions. Keep each rule narrow and explainable; let the
weights and the LLM reviewer combine them. Prefer a precise `bound_call` over a broad `regex`. A good rule
is one a reviewer can read and immediately understand why it fired.
