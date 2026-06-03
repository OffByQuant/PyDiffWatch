import json, urllib.request
from . import store
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

def emit(cfg, conn, verdict: Verdict, release_id: int):
    dedupe_key = f"{verdict.package}|{verdict.version}|{verdict.classification}"
    rules_json = json.dumps([r.__dict__ for r in verdict.fired_rules])
    is_new = store.record_alert(conn, release_id, verdict.classification,
                                verdict.score, rules_json, dedupe_key)
    if not is_new:
        return False                       # deduped — already alerted
    print(_render(verdict))
    if cfg.webhook_url:
        try:
            body = json.dumps({"text": _render(verdict)}).encode()
            req = urllib.request.Request(cfg.webhook_url, data=body,
                                         headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=cfg.fetch_timeout_s)
        except Exception:
            pass                           # alert already recorded; retry next run
    return True
