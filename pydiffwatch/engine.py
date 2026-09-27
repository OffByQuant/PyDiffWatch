"""Rules-engine triage: build facts from a diff, run the loaded ruleset over them, sum weights.

Emits `FiredRule` / `TriageResult` for the orchestrator/notifier/store. The detection opinions
live entirely in the loaded rules (`rules/community/*.yaml`); this module owns only scoring + scope
iteration."""
from .facts import build_facts
from .models import FiredRule, TriageResult
from .rules import evaluate


def _fire(rule, file_path, lines, loc_weight):
    w = rule.weight * (loc_weight if rule.location_scaled else 1.0)
    return FiredRule(rule.id, w, file_path, lines)


def score(fired, ruleset) -> float:
    """The release score: per rule, the sum of its fired weights, capped at its max_total. The per-file FiredRule
    weights stay whole; the cap is only on what one rule adds to the release."""
    total = 0.0
    for rule in ruleset:
        s = sum(f.weight for f in fired if f.rule == rule.id)
        total += s if rule.max_total is None else min(s, rule.max_total)
    return total


def triage(diff, cfg, ruleset, maintainer_context=None) -> TriageResult:
    facts = build_facts(diff, maintainer_context)
    fired = []
    for rule in ruleset:
        if rule.applies_to == "code":
            for f in facts.files:
                if evaluate(rule.match, f):
                    fired.append(_fire(rule, f.path, f.lines, f.location_weight))
        elif rule.applies_to == "binary":
            for b in facts.binaries:
                if evaluate(rule.match, b):
                    fired.append(_fire(rule, b.get("path", "?"), (0, 0), 1.0))
        elif rule.applies_to == "dep":
            for dep in facts.deps:
                if evaluate(rule.match, dep):
                    fired.append(_fire(rule, dep.get("name", "?"), (0, 0), 1.0))
        elif rule.applies_to == "maintainer":
            if evaluate(rule.match, facts.maintainer_changed):
                fired.append(_fire(rule, "<ownership>", (0, 0), 1.0))
    total = score(fired, ruleset)
    return TriageResult(total, fired, total >= cfg.threshold_t)
