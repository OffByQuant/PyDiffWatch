"""Rules-engine triage: build facts from a diff, run the loaded ruleset over them, sum weights.

Emits `FiredRule` / `TriageResult` for the orchestrator/notifier/store. The detection opinions
live entirely in the loaded rules (`rules/community/*.yaml`); this module owns only scoring + scope
iteration."""
from .facts import build_facts
from .models import FiredRule, TriageResult
from .rules import evaluate


def _fire(rule, file_path, lines, loc_weight):
    w = rule.weight * (loc_weight if rule.location_scaled else 1.0)
    return FiredRule(rule.id, w, file_path, lines), w


def triage(diff, cfg, ruleset, maintainer_context=None) -> TriageResult:
    facts = build_facts(diff, maintainer_context)
    fired, score = [], 0.0
    for rule in ruleset:
        rule_sum = 0.0
        if rule.applies_to == "code":
            for f in facts.files:
                if evaluate(rule.match, f):
                    fr, w = _fire(rule, f.path, f.lines, f.location_weight)
                    fired.append(fr)
                    rule_sum += w
        elif rule.applies_to == "binary":
            for b in facts.binaries:
                if evaluate(rule.match, b):
                    fr, w = _fire(rule, b.get("path", "?"), (0, 0), 1.0)
                    fired.append(fr)
                    rule_sum += w
        elif rule.applies_to == "dep":
            for dep in facts.deps:
                if evaluate(rule.match, dep):
                    fr, w = _fire(rule, dep.get("name", "?"), (0, 0), 1.0)
                    fired.append(fr)
                    rule_sum += w
        elif rule.applies_to == "maintainer":
            if evaluate(rule.match, facts.maintainer_changed):
                fr, w = _fire(rule, "<ownership>", (0, 0), 1.0)
                fired.append(fr)
                rule_sum += w
        # max_total caps what one rule adds to the release score; the per-file FiredRule weights stay whole.
        score += rule_sum if rule.max_total is None else min(rule_sum, rule.max_total)
    return TriageResult(score, fired, score >= cfg.threshold_t)
