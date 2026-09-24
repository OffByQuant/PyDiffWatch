from dataclasses import dataclass, field

@dataclass(frozen=True)
class NewRelease:
    package: str; version: str; serial: int
    new_release: bool = True     # the changelog's `new release` event (the release's first file upload)
    sdist_upload: bool = False   # its sdist upload event; re-scans a release left no_sdist_wait/no_sdist (wheels first)

@dataclass(frozen=True)
class ArtifactSet:
    package: str; version: str; prior_version: str | None
    basis: str
    new_files: dict[str, bytes]
    prior_files: dict[str, bytes]
    artifact_hashes: dict[str, str]
    added_binaries: list[dict] = field(default_factory=list)
    is_new_package: bool = False   # True = no prior version on PyPI (genuinely new codebase)
    maintainer_metadata: dict | None = None   # author/maintainer/ownership captured from PyPI JSON
    added_dep_findings: list[dict] = field(default_factory=list)   # signal 5: suspicious added deps
    prior_error: str | None = None   # the prior sdist couldn't be fetched, so this was diffed against nothing
    description: str | None = None   # this version's PyPI info.summary: the author's claim, context only
    too_large: tuple[str, ...] = ()  # this version's source members too large to scan (unfiltered by the prior)
    surface_omitted: int | None = None   # a first release under `surface`: source files the filter left out
    requires_dist_change: dict | None = None   # {"added": [...], "removed": [...]} Requires-Dist lines, when known

@dataclass(frozen=True)
class Hunk:
    old_range: tuple[int, int]; new_range: tuple[int, int]
    added: list[str]; removed: list[str]

@dataclass(frozen=True)
class FileDiff:
    path: str; change_kind: str; hunks: list[Hunk]   # added|removed|modified
    new_text: str | None = None                      # complete new-file source (for whole-file AST parse)

@dataclass(frozen=True)
class Diff:
    package: str; version: str; is_first_release: bool
    changed: list[FileDiff]; added_binaries: list[dict]
    added_dep_findings: list[dict] = field(default_factory=list)   # signal 5: suspicious added deps
    description: str = ""          # the new version's info.summary, one line: the author's claim, context only
    exec_context: str = ""         # how the new version's files run (build, startup, import, commands, plugins)
    baseline_unavailable: str = "" # the prior version whose sdist could not be fetched (diffed against nothing)
    surface_omitted: int | None = None   # a first release under `surface`: source files not shown
    signals: str = ""              # dependency / binary / ownership signals, one per line (author strings escaped)

@dataclass(frozen=True)
class FiredRule:
    rule: str; weight: float; file: str; lines: tuple[int, int]

@dataclass(frozen=True)
class TriageResult:
    score: float; fired_rules: list[FiredRule]; escalate: bool

@dataclass(frozen=True)
class Verdict:
    package: str; version: str; classification: str
    score: float; fired_rules: list[FiredRule]; urgent: bool
    # §7 LLM reviewer fields — None for heuristic-only alerts (containment refusals, LLM-down fallback)
    confidence: float | None = None
    attack_type: str | None = None
    reasoning: str | None = None
    cited_hunk: str | None = None
    recommended_action: str | None = None
    model: str | None = None          # which Claude model produced this verdict (-> verdicts.model)
