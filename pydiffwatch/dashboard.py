"""Local takedown dashboard: render persisted verdicts as a self-contained HTML
page (one card per reviewed package) with a direct PyPI link and, for flagged
packages, a one-click "Report malware on PyPI" action.

Pure functions only — no DB, no I/O. SECURITY: every string here is derived from
untrusted package content (name, version, cited code, LLM reasoning quoting code),
so all of it is html.escape'd and all URL path segments are urllib.parse.quote'd.
An XSS in the security dashboard would be a self-own.
"""
import html
from urllib.parse import quote

_PYPI = "https://pypi.org/project"
_FLAGGED = ("malicious", "suspicious")


def pypi_package_url(package: str) -> str:
    return f"{_PYPI}/{quote(package, safe='')}/"


def pypi_version_url(package: str, version: str) -> str:
    return f"{_PYPI}/{quote(package, safe='')}/{quote(version, safe='')}/"


def humanize_age(seconds) -> str:
    s = int(seconds)
    if s < 60:
        return "just now"
    for unit, size in (("day", 86400), ("hour", 3600), ("minute", 60)):
        if s >= size:
            n = s // size
            return f"{n} {unit}{'s' if n != 1 else ''} ago"
    return "just now"


def _conf_pct(conf) -> str:
    if conf is None:
        return "?"
    try:
        c = float(conf)
    except (TypeError, ValueError):
        return "?"
    if c <= 1.0:
        c *= 100.0
    return f"{int(round(c))}%"


def _is_not_scanned(row: dict) -> bool:
    """model == 'none' marks the UNREVIEWED placeholder verdict (fetch/extract refusal, quarantine,
    oversized input, ...): pydiffwatch never ran a model over this release at all."""
    return row.get("model") == "none"


def _is_partial(row: dict) -> bool:
    """A release the model DID review, but not in full — some flagged content was dropped from its input
    (spec U2). Detected by reasoning starting 'reviewed partially:' (orchestrator._clip_files) OR,
    independently of that wording (round 1, N2 — a reworded note must not silently stop being detected),
    by the same shape orchestrator._record routes there: a benign verdict parked in needs_adjudication by
    an actual model (model != 'none'; a not-scanned release reaching needs_adjudication is a different
    case, handled by _is_not_scanned)."""
    if (row.get("reasoning") or "").startswith("reviewed partially:"):
        return True
    return (row.get("stage") == "needs_adjudication"
            and (row.get("classification") or "").lower() == "benign"
            and row.get("model") not in (None, "none"))


def is_flagged(row: dict) -> bool:
    """A release needing a person's attention because the model itself called it malicious/suspicious,
    or because a human said so. A human adjudication (`human_label`) is the final word when present:
    'benign' clears the flag for good; any other label keeps it flagged even if the model's own
    classification was 'benign'. Absent a human label, a not-scanned release (model == 'none') is never
    flagged by this alone — its placeholder classification ('suspicious') is a queueing artifact, not a
    model finding, so it carries no "Report malware" button (spec: dashboard-brief.md)."""
    human = row.get("human_label")
    if human is not None:
        return human.lower() != "benign"
    if _is_not_scanned(row):
        return False
    cls = (row.get("classification") or "benign").lower()
    return cls in _FLAGGED


def _card(row: dict) -> str:
    # A human adjudication overrides the model's classification for display too, so the badge text
    # never contradicts is_flagged's styling/report-button decision above. Absent one, a not-scanned or
    # partial-review row gets its own badge (never 'suspicious'/'malicious' styling for not-scanned, per
    # dashboard-brief.md) instead of the raw model classification.
    human = row.get("human_label")
    cls = human.lower() if human is not None else (row.get("classification") or "benign").lower()
    not_scanned = human is None and _is_not_scanned(row)
    partial = human is None and not not_scanned and _is_partial(row)
    pkg = row.get("package") or ""
    ver = row.get("version") or ""
    e = html.escape
    flagged = is_flagged(row)
    if not_scanned:
        style_cls, badge_text = "not_scanned", "not scanned"
    elif partial:
        style_cls, badge_text = (cls if cls in _FLAGGED else "partial"), "partial review"
    else:
        style_cls = cls if cls in _FLAGGED else ("suspicious" if flagged else cls)   # benign-but-flagged reads as suspicious
        badge_text = cls
    model_line_html = (f'<div class="model-cls">model: {e(cls)}</div>' if partial else "")
    attack = row.get("attack_type") or ""
    attack_html = (f'<span class="k">attack</span><span class="v">{e(attack)}</span>'
                   if attack and attack != "none" else "")
    actions = [f'<a class="btn view" href="{e(pypi_version_url(pkg, ver))}" '
               f'target="_blank" rel="noopener noreferrer">View on PyPI ↗</a>']
    if flagged:
        actions.insert(0, f'<a class="btn report" href="{e(pypi_package_url(pkg))}" '
                       f'target="_blank" rel="noopener noreferrer">Report malware on PyPI ↗</a>')
    reasoning = row.get("reasoning") or ""
    cited = row.get("cited_hunk") or ""
    reason_html = f'<div class="reason">{e(reasoning)}</div>' if reasoning else ""
    cited_html = (f'<div class="cited"><span class="k">cited</span> {e(cited)}</div>'
                  if cited else "")
    human_html = ""
    if human:
        note = row.get("human_note") or ""
        model_cls = (row.get("classification") or "?").lower()
        human_html = (f'<div class="human">your verdict: {e(human)}{" — " + e(note) if note else ""}'
                      f'{f" · model said {e(model_cls)}" if model_cls != human.lower() else ""}</div>')
    triage = row.get("triage_score")
    triage_html = (f'<span class="k">triage</span><span class="v">{int(triage)}</span>'
                   if triage is not None else "")
    return f"""<div class="card {e(style_cls)}">
  <div class="head">
    <div class="pkg">{e(pkg)} <span class="ver">{e(ver)}</span></div>
    <div class="badge {e(style_cls)}">{e(badge_text)}</div>
  </div>
  <div class="meta">
    {triage_html}
    <span class="k">confidence</span><span class="v">{_conf_pct(row.get('confidence'))}</span>
    {attack_html}
    <span class="k">model</span><span class="v">{e(row.get('model') or '?')}</span>
  </div>
  {human_html}
  {model_line_html}
  {reason_html}
  {cited_html}
  <div class="actions">{''.join(actions)}</div>
</div>"""


_STYLE = """
:root{--bg:#0d1117;--panel:#161b22;--line:#30363d;--ink:#e6edf3;--muted:#8b949e;
  --red:#f85149;--amber:#d29922;--green:#3fb950;--mono:'SF Mono',ui-monospace,Menlo,monospace}
*{box-sizing:border-box;margin:0}
body{background:var(--bg);color:var(--ink);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:40px;max-width:1100px;margin:0 auto}
h1{font-size:24px;letter-spacing:-.3px}.sub{color:var(--muted);margin:6px 0 28px;font-size:15px}
.card{background:var(--panel);border:1px solid var(--line);border-left-width:4px;border-radius:12px;padding:20px 22px;margin-bottom:16px}
.card.malicious{border-left-color:var(--red)}.card.suspicious{border-left-color:var(--amber)}
.card.benign{border-left-color:#21372a;opacity:.78}
.card.not_scanned{border-left-color:var(--muted)}
.card.partial{border-left-color:#1f6feb}
.head{display:flex;justify-content:space-between;align-items:center;gap:12px}
.pkg{font-family:var(--mono);font-size:18px;font-weight:600}.ver{color:var(--muted);font-size:15px}
.badge{font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;padding:5px 12px;border-radius:999px}
.badge.malicious{background:#2d1416;border:1px solid var(--red);color:var(--red)}
.badge.suspicious{background:#241c08;border:1px solid var(--amber);color:var(--amber)}
.badge.benign{background:#0f2417;border:1px solid #2c5138;color:var(--green)}
.badge.not_scanned{background:#1c2128;border:1px solid var(--muted);color:var(--muted)}
.badge.partial{background:#0d1f2d;border:1px solid #1f6feb;color:#58a6ff}
.model-cls{font-size:13px;color:var(--muted);margin-bottom:10px}
.meta{display:flex;flex-wrap:wrap;align-items:center;gap:6px 10px;margin:14px 0;font-size:13px}
.meta .k{color:var(--muted);text-transform:uppercase;letter-spacing:.5px;font-size:11px}
.meta .v{font-family:var(--mono);margin-right:8px}
.reason{background:#0d1117;border:1px solid var(--line);border-radius:8px;padding:12px 14px;font-size:14px;line-height:1.55;color:#c9d1d9}
.human{margin-bottom:10px;font-size:13px;color:var(--ink);font-weight:600}
.cited{margin-top:8px;font-size:12.5px;color:var(--muted);font-family:var(--mono)}
.actions{display:flex;gap:10px;margin-top:14px}
.btn{font-size:13px;font-weight:600;text-decoration:none;padding:8px 14px;border-radius:8px;border:1px solid var(--line);color:var(--ink)}
.btn.report{background:#2d1416;border-color:var(--red);color:var(--red)}
.btn.view{color:#58a6ff}
.status{display:flex;flex-wrap:wrap;gap:8px 22px;align-items:center;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 18px;margin-bottom:24px;font-size:13px;color:var(--muted)}
.status .stat{display:flex;align-items:center;gap:7px}
.status code{font-family:var(--mono);color:var(--ink);font-size:12.5px}
.dot{width:9px;height:9px;border-radius:50%;display:inline-block}
.dot.ok{background:var(--green);box-shadow:0 0 6px var(--green)}
.dot.down{background:var(--red);box-shadow:0 0 6px var(--red)}
.dot.idle{background:var(--muted)}
.empty{color:var(--muted);padding:40px;text-align:center}
footer{color:var(--muted);font-size:12.5px;margin-top:28px;text-align:center}
"""


def _rank(row) -> int:
    # A human adjudication is the final word, as in is_flagged and the badge. Absent one: malicious,
    # then suspicious, then not-scanned/partial-review (a tool gap, not a model finding — still needs a
    # person, but doesn't outrank an actual model finding), then benign.
    human = row.get("human_label")
    cls = human.lower() if human is not None else (row.get("classification") or "").lower()
    if human is None and (_is_not_scanned(row) or _is_partial(row)):
        return 2
    if cls == "malicious":
        return 0
    if cls in _FLAGGED:
        return 1
    return 3


def counts(rows) -> dict:
    """Split verdict rows into model-reviewed vs not-scanned, and how many of the model-reviewed rows are
    flagged (model said malicious/suspicious, or a human overrode it so) or partial reviews. Shared by
    render_dashboard's sub-header and orchestrator.export_dashboard's status strip so the two can't drift
    apart.

    A human_label takes the row over entirely (round 1, item 2), same as the badge and is_flagged: a
    human 'malicious'/'suspicious' counts as flagged full stop, even on an otherwise not-scanned or
    partial-review release (it's no longer a tool gap -- a person looked at it); a human 'benign' counts
    as neither flagged, not-scanned, nor partial -- it's settled. Only rows with no human_label are ever
    counted into not_scanned or partial. model_reviewed is everything not counted as not_scanned, so a
    human-labelled row (whatever its underlying model field) always lands there."""
    not_scanned = sum(1 for r in rows if r.get("human_label") is None and _is_not_scanned(r))
    partial = sum(1 for r in rows if r.get("human_label") is None and not _is_not_scanned(r) and _is_partial(r))
    return {
        "model_reviewed": len(rows) - not_scanned,
        "model_flagged": sum(1 for r in rows if is_flagged(r)),
        "partial": partial,
        "not_scanned": not_scanned,
    }


def _counts_text(model_reviewed, model_flagged, partial, not_scanned) -> str:
    """The model-reviewed/flagged/partial/not-scanned phrase shared verbatim by the status strip and the
    sub-header (round 1, item 5: they must read identically). Partial reviews wait on a person just like
    not-scanned releases do, so both carry the "need manual review" cue."""
    return (f"{model_reviewed} model-reviewed ({model_flagged} flagged by the model, "
            f"{partial} partial review — need manual review) · {not_scanned} not scanned — need manual review")


def _status_strip(status: dict) -> str:
    e = html.escape
    reach = status.get("model_reachable")
    if reach is True:
        dot, model_txt = "ok", "model reachable"
    elif reach is False:
        dot, model_txt = "down", "model unreachable"
    else:
        dot, model_txt = "idle", "model not probed"
    age = status.get("last_poll_age") or "never"
    if status.get("stale") and status.get("last_poll_age"):
        age += " (stale)"
    serial = status.get("last_serial")
    serial_txt = str(serial) if serial is not None else "—"
    releases = int(status.get("releases_total") or 0)
    model_reviewed = int(status.get("model_reviewed_total") or 0)
    model_flagged = int(status.get("model_flagged_total") or 0)
    partial = int(status.get("partial_total") or 0)
    not_scanned = int(status.get("not_scanned_total") or 0)
    pending = status.get("pending_review") or {}
    pending_txt = (f"{sum(pending.values())} pending LLM review ("
                   + ", ".join(f"{k}: {v}" for k, v in sorted(pending.items())) + ")") if pending else ""
    retry = status.get("retry") or {}
    backlog = []
    if retry.get("retrying"):
        oldest = retry.get("oldest_retrying_age")
        backlog.append(f"{int(retry['retrying'])} scan(s) retrying"
                       + (f" (oldest first seen {oldest})" if oldest else ""))
    if retry.get("gave_up"):
        backlog.append(f"{int(retry['gave_up'])} scan(s) given up")
    retry_txt = " · ".join(backlog)
    from .guard import describe
    g = status.get("guard")
    guard_txt = describe(g) if g else ""
    return f"""<div class="status">
  <span class="stat"><span class="dot {dot}"></span>{e(model_txt)} <code>{e(status.get('reviewer') or '?')}</code></span>
  <span class="stat">last poll: {e(age)}</span>
  <span class="stat">cursor: {e(serial_txt)}</span>
  <span class="stat">{releases} releases · {_counts_text(model_reviewed, model_flagged, partial, not_scanned)}</span>
{f'  <span class="stat">{e(pending_txt)}</span>' + chr(10) if pending_txt else ''}{f'  <span class="stat">{e(retry_txt)}</span>' + chr(10) if retry_txt else ''}{f'  <span class="stat">{e(guard_txt)}</span>' + chr(10) if guard_txt else ''}</div>"""


def render_dashboard(rows, status: dict = None, generated_at: str = "") -> str:
    # flagged-first, independent of caller ordering (stable within each class).
    rows = sorted((dict(r) for r in rows), key=_rank)
    c = counts(rows)
    cards = "\n".join(_card(dict(r)) for r in rows) if rows else \
        '<div class="empty">No verdicts yet. Run <code>pydiffwatch run</code> first.</div>'
    gen = f" · generated {html.escape(generated_at)}" if generated_at else ""
    strip = _status_strip(status) if status else ""
    sub = _counts_text(c["model_reviewed"], c["model_flagged"], c["partial"], c["not_scanned"])
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PyDiffWatch — verdicts</title><style>{_STYLE}</style></head><body>
<h1>PyDiffWatch — supply-chain verdicts</h1>
<div class="sub">{sub}{gen}</div>
{strip}
{cards}
<footer>Flagged a real attack? Open it on PyPI and use “Report malware” for takedown. Static, no-execution analysis · 100% local.</footer>
</body></html>"""
