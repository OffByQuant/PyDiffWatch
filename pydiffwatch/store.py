import sqlite3, datetime, json
from .config import Config

SCHEMA = """
CREATE TABLE IF NOT EXISTS cursor(id INTEGER PRIMARY KEY CHECK(id=1),
  last_serial INTEGER NOT NULL DEFAULT 0, updated_at TEXT);
INSERT OR IGNORE INTO cursor(id, last_serial) VALUES (1, 0);
CREATE TABLE IF NOT EXISTS releases(id INTEGER PRIMARY KEY,
  package TEXT, version TEXT, serial INTEGER, is_first_release INTEGER,
  prior_version TEXT, artifact_basis TEXT, triage_score REAL, triage_rules TEXT,
  stage TEXT, processed_at TEXT, evidence TEXT, UNIQUE(package, version));
CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, release_id INTEGER,
  classification TEXT, score REAL, fired_rules TEXT, dedupe_key TEXT UNIQUE,
  delivery_status TEXT, sent_at TEXT);
CREATE TABLE IF NOT EXISTS verdicts(id INTEGER PRIMARY KEY,
  release_id INTEGER UNIQUE, classification TEXT, confidence REAL,
  attack_type TEXT, reasoning TEXT, cited_hunk TEXT, model TEXT, urgent INTEGER,
  created_at TEXT, human_label TEXT, human_note TEXT, adjudicated_at TEXT);
"""

def _now(): return datetime.datetime.now(datetime.UTC).isoformat()

def connect(cfg: Config) -> sqlite3.Connection:
    cfg.db_path.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(cfg.db_path)
    c.execute("PRAGMA journal_mode=WAL"); c.row_factory = sqlite3.Row
    return c

def init_schema(conn): conn.executescript(SCHEMA); conn.commit(); migrate_schema(conn)

def migrate_schema(conn):
    """Additive, idempotent migrations for DBs created before a column existed (no migration framework;
    the production .sqlite predates maintainer_metadata). Probe-then-ALTER; ADD COLUMN with no default is
    an O(1) metadata-only op that backfills NULL — it never rewrites or loses existing rows."""
    try:
        conn.execute("SELECT maintainer_metadata FROM releases LIMIT 1")
    except sqlite3.OperationalError:
        conn.execute("ALTER TABLE releases ADD COLUMN maintainer_metadata TEXT"); conn.commit()
    try:
        conn.execute("SELECT evidence FROM releases LIMIT 1")
    except sqlite3.OperationalError:
        conn.execute("ALTER TABLE releases ADD COLUMN evidence TEXT"); conn.commit()

def get_last_serial(conn) -> int:
    return conn.execute("SELECT last_serial FROM cursor WHERE id=1").fetchone()[0]

def set_last_serial(conn, serial: int):
    conn.execute("UPDATE cursor SET last_serial=?, updated_at=? WHERE id=1", (serial, _now()))
    conn.commit()

def release_exists(conn, package, version) -> bool:
    return conn.execute("SELECT 1 FROM releases WHERE package=? AND version=?",
                        (package, version)).fetchone() is not None

def record_release(conn, package, version, serial, is_first, prior, basis, stage="ingested") -> int:
    conn.execute("""INSERT OR IGNORE INTO releases
        (package,version,serial,is_first_release,prior_version,artifact_basis,stage,processed_at)
        VALUES(?,?,?,?,?,?,?,?)""",
        (package, version, serial, int(is_first), prior, basis, stage, _now()))
    conn.commit()
    return conn.execute("SELECT id FROM releases WHERE package=? AND version=?",
                        (package, version)).fetchone()[0]

def set_baseline(conn, release_id, prior_version, is_first):
    """Record the baseline resolved from PyPI (the predecessor version, or None for a genuinely new
    package). Overwrites the provisional values from record_release — incl. on a retry."""
    conn.execute("UPDATE releases SET prior_version=?, is_first_release=? WHERE id=?",
                 (prior_version, int(is_first), release_id))
    conn.commit()

def update_release_metadata(conn, release_id, maintainer_metadata_json):
    """Persist the maintainer metadata captured from PyPI (JSON TEXT) on the release row."""
    conn.execute("UPDATE releases SET maintainer_metadata=? WHERE id=?",
                 (maintainer_metadata_json, release_id))
    conn.commit()

def update_evidence(conn, release_id, evidence_text):
    """Persist the flagged payload code (rendered diff TEXT) for a release. Stored INERT — never
    written to an executable path, never run (§0 containment). Self-contained evidence for a PyPI
    takedown report that survives a device move and the package being pulled from PyPI."""
    conn.execute("UPDATE releases SET evidence=? WHERE id=?", (evidence_text, release_id))
    conn.commit()

def get_evidence(conn, release_id):
    """The stored flagged payload code for a release (TEXT), or None if absent. Read-only accessor for
    `diffwatch evidence <release_id>` — works for any release, not just the adjudication queue."""
    row = conn.execute("SELECT evidence FROM releases WHERE id=?", (release_id,)).fetchone()
    return row[0] if row else None

def releases_needing_evidence(conn, release_id=None, all_flagged=False):
    """Flagged releases whose payload was never captured (evidence IS NULL) — the backfill target set.

    Default = the REPORTABLE set: rows with a malicious/suspicious verdict or a non-benign alert (what
    you'd actually file a PyPI takedown for). all_flagged=True widens to every release with >=1 fired
    rule (includes benign-verdict sub-threshold rows — far more, far more network). release_id restricts
    to a single row regardless of scope."""
    base = ("SELECT DISTINCT r.id AS release_id, r.package, r.version, r.serial, "
            "r.is_first_release FROM releases r")
    where = ["r.evidence IS NULL", "r.triage_rules IS NOT NULL", "r.triage_rules != '[]'"]
    params = []
    if not all_flagged:
        base += (" LEFT JOIN verdicts v ON v.release_id = r.id"
                 " LEFT JOIN alerts a ON a.release_id = r.id")
        where.append("(v.classification IN ('malicious','suspicious') "
                     "OR (a.classification IS NOT NULL AND a.classification != 'benign'))")
    if release_id is not None:
        where.append("r.id = ?"); params.append(release_id)
    return conn.execute(base + " WHERE " + " AND ".join(where) + " ORDER BY r.id", params).fetchall()

def get_release_metadata(conn, package, version):
    """The stored maintainer metadata for a (package, version) as a dict, or None if absent/unset.
    Used to diff the current owner set against the prior release we recorded (maintainer-set-change)."""
    row = conn.execute("SELECT maintainer_metadata FROM releases WHERE package=? AND version=?",
                       (package, version)).fetchone()
    return json.loads(row[0]) if row and row[0] else None

def update_stage(conn, release_id, stage, score=None, rules=None):
    sets = ["stage=?"]; params = [stage]
    if score is not None:
        sets.append("triage_score=?"); params.append(score)
    if rules is not None:
        sets.append("triage_rules=?"); params.append(rules)
    params.append(release_id)
    conn.execute(f"UPDATE releases SET {', '.join(sets)} WHERE id=?", params)
    conn.commit()

def record_alert(conn, release_id, classification, score, fired_rules_json, dedupe_key) -> bool:
    cur = conn.execute("""INSERT OR IGNORE INTO alerts
        (release_id,classification,score,fired_rules,dedupe_key,delivery_status,sent_at)
        VALUES(?,?,?,?,?,?,?)""",
        (release_id, classification, score, fired_rules_json, dedupe_key, "pending", _now()))
    conn.commit()
    return cur.rowcount == 1   # True = newly inserted, False = deduped

def record_verdict(conn, release_id, verdict) -> int:
    """Persist an LLM Verdict (§5 verdicts table). UNIQUE(release_id) -> a re-review replaces."""
    conn.execute("""INSERT INTO verdicts
        (release_id,classification,confidence,attack_type,reasoning,cited_hunk,model,urgent,created_at)
        VALUES(?,?,?,?,?,?,?,?,?)
        ON CONFLICT(release_id) DO UPDATE SET
          classification=excluded.classification, confidence=excluded.confidence,
          attack_type=excluded.attack_type, reasoning=excluded.reasoning,
          cited_hunk=excluded.cited_hunk, model=excluded.model,
          urgent=excluded.urgent, created_at=excluded.created_at""",
        (release_id, verdict.classification, verdict.confidence, verdict.attack_type,
         verdict.reasoning, verdict.cited_hunk, verdict.model, int(verdict.urgent), _now()))
    conn.commit()
    return conn.execute("SELECT id FROM verdicts WHERE release_id=?", (release_id,)).fetchone()[0]

def get_stage(conn, package, version):
    row = conn.execute("SELECT stage FROM releases WHERE package=? AND version=?",
                       (package, version)).fetchone()
    return row[0] if row else None

def pending_adjudication(conn):
    """Suspicious LLM verdicts queued for agent review (§8.1): stage 'needs_adjudication' and not yet
    labelled. Joined with the release so the caller can re-fetch the diff."""
    return conn.execute(
        """SELECT r.id AS release_id, r.package, r.version, r.serial, r.triage_score, r.triage_rules,
                  r.evidence,
                  v.classification, v.confidence, v.attack_type, v.reasoning, v.cited_hunk, v.model
           FROM releases r JOIN verdicts v ON v.release_id = r.id
           WHERE r.stage = 'needs_adjudication' AND v.human_label IS NULL
           ORDER BY r.id""").fetchall()

def adjudicate(conn, release_id, label, note):
    """Record the agent's adjudication on a verdict; returns the release row (for alerting) or None."""
    conn.execute("UPDATE verdicts SET human_label=?, human_note=?, adjudicated_at=? WHERE release_id=?",
                 (label, note, _now(), release_id))
    conn.commit()
    return conn.execute("SELECT package, version, serial, triage_score, triage_rules "
                        "FROM releases WHERE id=?", (release_id,)).fetchone()

# Phase 1 LIMITATION (two issues, both fixed by PEP 440 ordering in Phase 3, spec §3.1):
#  1. Lexicographic compare: "1.9" < "1.10" is False, so multi-digit jumps pick a wrong baseline.
#  2. ORDER BY serial DESC returns the most-recently-INGESTED lower version, not the highest
#     version, so out-of-order ingestion can also pick a wrong baseline.
def prior_version(conn, package, version):
    row = conn.execute("""SELECT version FROM releases WHERE package=? AND version<?
        ORDER BY serial DESC LIMIT 1""", (package, version)).fetchone()
    return row[0] if row else None
