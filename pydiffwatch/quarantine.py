"""Confirmed-malicious packages — DiffWatch must NEVER download, process, or (under any circumstances)
install these. This is a static denylist of supply-chain malware confirmed by review. fetch_artifacts()
hard-refuses any entry before a single byte is pulled, so DiffWatch won't re-ingest them on later ticks.

IMPORTANT: DiffWatch has no install path of ANY kind — no pip/subprocess/extractall/import/exec/eval;
analyzed packages are only ever read as bytes in memory and parsed (ast.parse) as text. This list is
therefore the canonical 'never touch' record + defense-in-depth, NOT the only barrier. Preventing a
*manual* `pip install <name>` on this host requires a host-level block (a PIP_CONSTRAINT denylist),
which is outside DiffWatch's process boundary."""
import re


def _norm(name: str) -> str:
    """PEP 503 normalization: lowercase, collapse runs of -_. to a single dash. PyPI treats
    Cud_Request / cud-request / CUDREQUEST as one project, so the denylist must match all spellings."""
    return re.sub(r"[-_.]+", "-", (name or "").strip().lower())


# Maintainer `rrdrqup` (PyPI account created 2026-05-30) pushed these three in a burst. Quarantined
# as deceptive typosquats — never fetch/process/install. Static review (verdicts in DB):
#   - cudrequest   : typosquat of `requests`; ships an insecure PHP login app — NO active payload.
#   - pythondocxx  : typosquat of `python-docx`; an OpenRouter AI CLI — NO active payload.
#   - requestspillows: wheel-only, NOT yet inspected — precautionary; malice UNCONFIRMED (revisit).
KNOWN_MALICIOUS = frozenset({"cudrequest", "pythondocxx", "requestspillows"})


def is_quarantined(package: str) -> bool:
    return _norm(package) in KNOWN_MALICIOUS
