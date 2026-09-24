import json, urllib.request
from . import store, egress
from .models import Verdict

def _render(v: Verdict) -> str:
    top = sorted(v.fired_rules, key=lambda r: -r.weight)[:5]
    rules = "; ".join(f"{r.rule}@{r.file}:{r.lines[0]}-{r.lines[1]}" for r in top)
    line = (f"[DIFFWATCH] {v.classification} score={v.score:.0f} "
            f"{v.package} {v.version} :: {rules}")
    if v.reasoning is not None:        # LLM verdict — add §7 fields
        conf = f"{v.confidence:.2f}" if v.confidence is not None else "?"
        line += (f"\n  attack={v.attack_type} confidence={conf} model={v.model}"
                 f"\n  cited_hunk={v.cited_hunk}\n  reason: {v.reasoning}")
    return line

def post_webhook(cfg, text) -> bool:
    """POST {"text": text} to cfg.webhook_url. False when none is set or delivery failed; never raises,
    because an alert must not break a scan."""
    if not cfg.webhook_url:
        return False
    try:
        egress.assert_web_scheme(cfg.webhook_url)
        body = json.dumps({"text": text}).encode()
        req = urllib.request.Request(cfg.webhook_url, data=body, headers={"Content-Type": "application/json"})
        # webhook_url is operator config (scheme-guarded above), never package data.
        urllib.request.urlopen(req, timeout=cfg.fetch_timeout_s)  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        return True
    except Exception:
        return False


def emit(cfg, conn, verdict: Verdict, release_id: int, dedupe_suffix: str = ""):
    """Print and post one alert, at most once per package|version|classification[|dedupe_suffix]. The suffix
    lets a second, different alert for the same release through (e.g. an unscanned outcome after the
    first-park heuristic alert) while a re-tick of either is still deduped."""
    dedupe_key = f"{verdict.package}|{verdict.version}|{verdict.classification}"
    if dedupe_suffix:
        dedupe_key += f"|{dedupe_suffix}"
    rules_json = json.dumps([r.__dict__ for r in verdict.fired_rules])
    is_new = store.record_alert(conn, release_id, verdict.classification,
                                verdict.score, rules_json, dedupe_key)
    if not is_new:
        return False                       # deduped — already alerted
    print(_render(verdict))
    post_webhook(cfg, _render(verdict))    # alert already recorded; a failed delivery never breaks a scan
    return True
