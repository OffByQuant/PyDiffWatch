"""Declarative rule format: loader, fail-closed validator, and a safe matcher.

A rule is structured YAML — `match` is a nested boolean tree (all/any/not) over predicate-dict leaves.
The matcher (`evaluate`) is a PURE DATA WALK: no eval, no exec, no import, no expression strings. A rule
that fails validation (unknown predicate, wrong-scope predicate, bad enum, malformed tree) is dropped at
load time with a logged warning and never evaluated. This is what makes a community-contributed YAML file
safe to load without sandboxing — it can describe matches but can never execute code."""
import logging
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

CATEGORIES = {"decode", "exec", "process", "network", "credential"}
BINARY_REASONS = {"source-too-large", "foreign-language-source", "new-binary"}
DEP_REASONS = {"typosquat", "nonexistent", "brand-new"}
SCOPES = {"code", "binary", "dep", "maintainer"}
_BOOL = {"all", "any", "not"}
MAX_REGEX_LEN = 1000   # bound a community-supplied regex (memory at load + ReDoS surface at match time)
# predicate name -> set of scopes it is valid in
_PRED_SCOPE = {
    "bound_call": {"code"}, "import_present": {"code"}, "regex": {"code"},
    "blob_present": {"code"}, "syntax_error": {"code"}, "location_at_least": {"code"},
    "binary_reason": {"binary"}, "dep_reason": {"dep"}, "maintainer_changed": {"maintainer"},
}


@dataclass(frozen=True)
class Rule:
    id: str
    applies_to: str
    weight: float
    match: dict
    attack_type: str = ""
    location_scaled: bool = False
    description: str = ""


def _valid_pred_args(name, args, scope) -> bool:
    if scope not in _PRED_SCOPE.get(name, set()):
        return False
    if name == "bound_call":
        if not isinstance(args, dict) or not args or set(args) - {"category", "name"}:
            return False
        if "category" in args:
            cats = args["category"]
            cats = cats if isinstance(cats, list) else [cats]
            if not cats or not all(c in CATEGORIES for c in cats):
                return False
        if "name" in args and not isinstance(args["name"], str):
            return False
        return True
    if name == "import_present":
        return isinstance(args, dict) and isinstance(args.get("module"), str)
    if name == "regex":
        if not (isinstance(args, dict) and isinstance(args.get("pattern"), str)):
            return False
        if len(args["pattern"]) > MAX_REGEX_LEN:
            return False
        try:
            re.compile(args["pattern"])
        except re.error:
            return False
        return True
    if name in ("blob_present", "syntax_error", "maintainer_changed"):
        return args is True
    if name == "location_at_least":
        return isinstance(args, (int, float)) and not isinstance(args, bool)
    if name == "binary_reason":
        return isinstance(args, str) and args in BINARY_REASONS
    if name == "dep_reason":
        return isinstance(args, str) and args in DEP_REASONS
    return False


def _valid_match(node, scope) -> bool:
    if not isinstance(node, dict) or len(node) != 1:
        return False
    (key, val), = node.items()
    if key in _BOOL:
        if key == "not":
            return _valid_match(val, scope)
        return isinstance(val, list) and len(val) >= 1 and all(_valid_match(n, scope) for n in val)
    if key in _PRED_SCOPE:
        return _valid_pred_args(key, val, scope)
    return False


def validate_rule(raw):
    """Return a validated Rule, or None (with a logged warning) if anything is wrong. Fail-closed."""
    if not isinstance(raw, dict):
        logger.warning("rule rejected (not a mapping): %r", raw)
        return None
    try:
        rid = raw["id"]
        scope = raw["applies_to"]
        weight = float(raw["weight"])
        match = raw["match"]
    except (KeyError, TypeError, ValueError):
        logger.warning("rule rejected (missing/invalid required field): %r", raw)
        return None
    # Wrap _valid_match defensively: validation must NEVER raise into the loader (fail-closed). A
    # malformed predicate arg (e.g. an unhashable list where a string enum is expected) returns None
    # and is dropped with a warning, never crashing the load of the whole ruleset.
    try:
        ok = scope in SCOPES and _valid_match(match, scope)
    except Exception as e:
        logger.warning("rule %r rejected: validation error: %s", raw.get("id"), e)
        return None
    if not ok:
        logger.warning("rule %r rejected: bad scope or match tree", raw.get("id"))
        return None
    return Rule(id=str(rid), applies_to=scope, weight=weight, match=match,
                attack_type=str(raw.get("attack_type", "")),
                location_scaled=bool(raw.get("location_scaled", False)),
                description=str(raw.get("description", "")))


def load_rules(rules_dir) -> list:
    """Load and validate every rule in `rules_dir`/*.yaml. Invalid rules and duplicate ids are dropped."""
    rules, seen = [], set()
    for path in sorted(Path(rules_dir).glob("*.yaml")):
        try:
            docs = yaml.safe_load(path.read_text()) or []
        except yaml.YAMLError as e:
            logger.warning("skipping unparseable rule file %s: %s", path, e)
            continue
        for raw in (docs if isinstance(docs, list) else [docs]):
            r = validate_rule(raw)
            if r is None:
                continue
            if r.id in seen:
                logger.warning("duplicate rule id %r in %s, skipping", r.id, path)
                continue
            seen.add(r.id)
            rules.append(r)
    return rules


def _pred(name, args, ctx) -> bool:
    if name == "bound_call":
        if "category" in args:
            cats = args["category"]
            cats = cats if isinstance(cats, list) else [cats]
            if any(c in ctx.bound_categories for c in cats):
                return True
        if "name" in args and args["name"] in ctx.bound_names:
            return True
        return False
    if name == "import_present":
        return args["module"] in ctx.imported_modules
    if name == "regex":
        return any(re.search(args["pattern"], s) for s in ctx.added_strs)
    if name == "blob_present":
        return ctx.blob_present
    if name == "syntax_error":
        return ctx.syntax_error
    if name == "location_at_least":
        return ctx.location_weight >= args
    if name == "binary_reason":
        return ctx.get("reason") == args
    if name == "dep_reason":
        return ctx.get("reason") == args
    if name == "maintainer_changed":
        return ctx is True
    return False


def evaluate(node, ctx) -> bool:
    """Recursively evaluate a validated match tree against a scope context. Pure data walk."""
    (key, val), = node.items()
    if key == "all":
        return all(evaluate(n, ctx) for n in val)
    if key == "any":
        return any(evaluate(n, ctx) for n in val)
    if key == "not":
        return not evaluate(val, ctx)
    return _pred(key, val, ctx)
