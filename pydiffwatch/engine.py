"""Rules-engine triage: build facts from a diff, run the loaded ruleset over them, sum weights.

Drop-in replacement for main DiffWatch's hardwired `triage.triage`, emitting the same public types
(`FiredRule`, `TriageResult`) so the orchestrator/notifier/store are unchanged. The detection opinions
live entirely in the loaded rules (`rules/community/*.yaml`); this module owns only scoring + scope
iteration. The decode->exec taint chain and production-tuned weights are NOT here (held back upstream)."""
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
        if rule.applies_to == "code":
            for f in facts.files:
                if evaluate(rule.match, f):
                    fr, w = _fire(rule, f.path, f.lines, f.location_weight)
                    fired.append(fr)
                    score += w
        elif rule.applies_to == "binary":
            for b in facts.binaries:
                if evaluate(rule.match, b):
                    fr, w = _fire(rule, b.get("path", "?"), (0, 0), 1.0)
                    fired.append(fr)
                    score += w
        elif rule.applies_to == "dep":
            for dep in facts.deps:
                if evaluate(rule.match, dep):
                    fr, w = _fire(rule, dep.get("name", "?"), (0, 0), 1.0)
                    fired.append(fr)
                    score += w
        elif rule.applies_to == "maintainer":
            if evaluate(rule.match, facts.maintainer_changed):
                fr, w = _fire(rule, "<ownership>", (0, 0), 1.0)
                fired.append(fr)
                score += w
    return TriageResult(score, fired, score >= cfg.threshold_t)
