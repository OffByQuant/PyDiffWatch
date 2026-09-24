import sqlite3, datetime, json, zlib
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
CREATE TABLE IF NOT EXISTS reviewer_stats(endpoint TEXT, model TEXT, tok_s REAL, chars_per_token REAL,
  samples INTEGER, state TEXT, detail TEXT, paused_until REAL, slow_streak INTEGER, updated_at TEXT,
  PRIMARY KEY(endpoint, model));
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
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
    for col, typ in (("review_attempts", "INTEGER DEFAULT 0"), ("pending_reason", "TEXT"),
                     ("pending_detail", "TEXT"), ("review_input", "BLOB"),
                     ("fetch_attempts", "INTEGER DEFAULT 0"), ("fetch_note", "TEXT")):
        try:
            conn.execute(f"SELECT {col} FROM releases LIMIT 1")
        except sqlite3.OperationalError:
            conn.execute(f"ALTER TABLE releases ADD COLUMN {col} {typ}"); conn.commit()
    try:
        conn.execute("SELECT review_input_chars FROM releases LIMIT 1")
    except sqlite3.OperationalError:
        conn.execute("ALTER TABLE releases ADD COLUMN review_input_chars INTEGER")
        for rid, blob in conn.execute("SELECT id, review_input FROM releases "
                                      "WHERE review_input IS NOT NULL").fetchall():
            conn.execute("UPDATE releases SET review_input_chars=? WHERE id=?",
                         (len(zlib.decompress(blob).decode()), rid))
        conn.commit()

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
    takedown report that survives a device move and the package being pulled from PyPI. Compressed."""
    conn.execute("UPDATE releases SET evidence=? WHERE id=?", (zlib.compress(evidence_text.encode()), release_id))
    conn.commit()

def clear_evidence(conn, release_id):
    conn.execute("UPDATE releases SET evidence=NULL WHERE id=?", (release_id,))
    conn.commit()

def evidence_text(value):
    """Stored evidence as text: compressed bytes, or plain text written by older versions."""
    if value is None or isinstance(value, str):
        return value
    return zlib.decompress(value).decode()

def get_evidence(conn, release_id):
    """The stored flagged payload code for a release (TEXT), or None if absent. Read-only accessor for
    `diffwatch evidence <release_id>` — works for any release, not just the adjudication queue."""
    row = conn.execute("SELECT evidence FROM releases WHERE id=?", (release_id,)).fetchone()
    return evidence_text(row[0]) if row else None

def prune(conn, retention_days: int = 0):
    """Shrink the database, keeping everything a person may act on (verdicts, alerts, the review queues and
    their evidence):
    - drop evidence nobody needs: releases reviewed benign, and releases below the review threshold;
    - compress the remaining evidence stored as plain text by older versions;
    - with retention_days > 0, delete plain release rows older than that (no verdict, no alert, not in an
      actionable stage), except each package's newest release, and its newest release carrying maintainer
      metadata, which get_release_metadata reads as the next release's maintainer baseline;
    then compact the file."""
    conn.execute("UPDATE releases SET evidence=NULL WHERE evidence IS NOT NULL AND (stage='triaged' OR id IN "
                 "(SELECT release_id FROM verdicts WHERE classification='benign' "
                 "AND COALESCE(human_label,'benign')='benign'))")
    last = 0    # compress in id-keyed batches, so a large legacy database is never held in memory at once
    while rows := conn.execute("SELECT id, evidence FROM releases WHERE typeof(evidence)='text' AND id > ? "
                               "ORDER BY id LIMIT 500", (last,)).fetchall():
        for rid, text in rows:
            conn.execute("UPDATE releases SET evidence=? WHERE id=?", (zlib.compress(text.encode()), rid))
        conn.commit()
        last = rows[-1][0]
    if retention_days > 0:
        cutoff = (datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=retention_days)).isoformat()
        # Kept stages a person may still act on: the adjudication queue, refused (never-scanned) releases, the
        # LLM-review queue, and metadata downloads still retrying or given up on (both shown by `pending`).
        # Partitioning by (package, has metadata) keeps the newest row overall and the newest with metadata:
        # PyPI's predecessor skips versions without an sdist, which have no maintainer metadata.
        conn.execute("DELETE FROM releases WHERE processed_at < ? "
                     "AND stage NOT IN ('pending_review','needs_adjudication','refused_to_extract',"
                     "'refused_to_fetch','metadata_retry','gave_up') "
                     "AND id NOT IN (SELECT release_id FROM verdicts WHERE release_id IS NOT NULL) "
                     "AND id NOT IN (SELECT release_id FROM alerts WHERE release_id IS NOT NULL) "
                     "AND id NOT IN (SELECT id FROM (SELECT id, ROW_NUMBER() OVER (PARTITION BY package, "
                     "maintainer_metadata IS NULL ORDER BY processed_at DESC, id DESC) AS n FROM releases) "
                     "WHERE n = 1)", (cutoff,))
    conn.commit()
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.execute("VACUUM")

def maybe_prune(conn, retention_days: int, every_s: float, now: float) -> bool:
    """prune() if the last one (recorded in the database, so cron-driven `run` counts too) is every_s old."""
    row = conn.execute("SELECT value FROM meta WHERE key='last_prune'").fetchone()
    if row and now - float(row[0]) < every_s:
        return False
    prune(conn, retention_days)
    conn.execute("INSERT INTO meta(key, value) VALUES('last_prune', ?) "
                 "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(now),))
    conn.commit()
    return True

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
    # `where` is code-controlled literal fragments only; every user value is a bound `?` param (sqlite3, not SQLAlchemy).
    return conn.execute(base + " WHERE " + " AND ".join(where) + " ORDER BY r.id", params).fetchall()  # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query

def get_release_metadata(conn, package, version):
    """The stored maintainer metadata for a (package, version) as a dict, or None if absent/unset.
    Used to diff the current owner set against the prior release we recorded (maintainer-set-change)."""
    row = conn.execute("SELECT maintainer_metadata FROM releases WHERE package=? AND version=?",
                       (package, version)).fetchone()
    return json.loads(row[0]) if row and row[0] else None

def review_attempts(conn, release_id) -> int:
    return conn.execute("SELECT review_attempts FROM releases WHERE id=?", (release_id,)).fetchone()[0] or 0

def bump_review_attempts(conn, release_id) -> int:
    conn.execute("UPDATE releases SET review_attempts=COALESCE(review_attempts,0)+1 WHERE id=?", (release_id,))
    conn.commit()
    return review_attempts(conn, release_id)

def park_for_review(conn, release_id, reason, detail, review_input):
    """Queue a flagged release for a later LLM review. The review input is kept (compressed) so the
    review doesn't depend on PyPI still hosting the sdist; it is dropped once a verdict lands."""
    conn.execute("UPDATE releases SET stage='pending_review', pending_reason=?, pending_detail=?, "
                 "review_input=?, review_input_chars=? WHERE id=?",
                 (reason, detail, zlib.compress(review_input.encode()), len(review_input), release_id))
    conn.commit()

def clear_pending(conn, release_id):
    conn.execute("UPDATE releases SET pending_reason=NULL, pending_detail=NULL, review_input=NULL, "
                 "review_input_chars=NULL WHERE id=?",
                 (release_id,))
    conn.commit()

def pending_reviews(conn, reasons=None, max_chars=None):
    sql = ("SELECT id AS release_id, package, version, triage_score, triage_rules, pending_reason, "
           "pending_detail, COALESCE(review_attempts,0) AS review_attempts, review_input "
           "FROM releases WHERE stage='pending_review'")
    params = list(reasons or [])
    if params:
        sql += f" AND pending_reason IN ({','.join('?' * len(params))})"
    if max_chars is not None:
        sql += " AND review_input_chars <= ?"
        params.append(max_chars)
    return conn.execute(sql + " ORDER BY id", params).fetchall()

def review_input(row) -> str:
    return zlib.decompress(row["review_input"]).decode()

METADATA_ATTEMPTS = 4    # failed metadata downloads before a release is given up on (visibly, in `pending`)


def note_metadata_failure(conn, release_id, detail) -> str:
    """Count a failed metadata download; the release waits in `metadata_retry` (retried each tick, off the
    cursor) until it has failed METADATA_ATTEMPTS times, then `gave_up`. Returns the new stage."""
    conn.execute("UPDATE releases SET fetch_attempts=COALESCE(fetch_attempts,0)+1, fetch_note=? WHERE id=?",
                 (detail, release_id))
    n = conn.execute("SELECT fetch_attempts FROM releases WHERE id=?", (release_id,)).fetchone()[0]
    stage = "gave_up" if n >= METADATA_ATTEMPTS else "metadata_retry"
    conn.execute("UPDATE releases SET stage=? WHERE id=?", (stage, release_id))
    conn.commit()
    return stage

def set_fetch_note(conn, release_id, note):
    conn.execute("UPDATE releases SET fetch_note=? WHERE id=?", (note, release_id))
    conn.commit()

def metadata_retries_due(conn, limit=20):
    return conn.execute("SELECT package, version, serial FROM releases WHERE stage='metadata_retry' "
                        "ORDER BY serial LIMIT ?", (limit,)).fetchall()

def metadata_retry_counts(conn) -> dict:
    r = conn.execute("SELECT COALESCE(SUM(stage='metadata_retry'),0), COALESCE(SUM(stage='gave_up'),0) "
                     "FROM releases").fetchone()
    return {"retrying": r[0], "gave_up": r[1]}

def get_reviewer_stats(conn, endpoint, model):
    row = conn.execute("SELECT tok_s, chars_per_token, samples, state, detail, paused_until, slow_streak "
                       "FROM reviewer_stats WHERE endpoint=? AND model=?", (endpoint, model)).fetchone()
    return dict(row) if row else None

def save_reviewer_stats(conn, endpoint, model, *, tok_s, chars_per_token, samples, state, detail,
                        paused_until, slow_streak):
    conn.execute("""INSERT INTO reviewer_stats(endpoint, model, tok_s, chars_per_token, samples, state, detail,
                        paused_until, slow_streak, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(endpoint, model) DO UPDATE SET tok_s=excluded.tok_s,
                        chars_per_token=excluded.chars_per_token, samples=excluded.samples,
                        state=excluded.state, detail=excluded.detail, paused_until=excluded.paused_until,
                        slow_streak=excluded.slow_streak, updated_at=excluded.updated_at""",
                 (endpoint, model, tok_s, chars_per_token, samples, state, detail, paused_until,
                  slow_streak, _now()))
    conn.commit()

def pending_review_counts(conn) -> dict:
    return dict(conn.execute("SELECT pending_reason, count(*) FROM releases WHERE stage='pending_review' "
                             "GROUP BY pending_reason").fetchall())

def update_stage(conn, release_id, stage, score=None, rules=None):
    sets = ["stage=?"]; params = [stage]
    if score is not None:
        sets.append("triage_score=?"); params.append(score)
    if rules is not None:
        sets.append("triage_rules=?"); params.append(rules)
    params.append(release_id)
    # `sets` is code-controlled column=? fragments only; every value is a bound `?` param (sqlite3, not SQLAlchemy).
    conn.execute(f"UPDATE releases SET {', '.join(sets)} WHERE id=?", params)  # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query
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
                  r.evidence, r.stage,
                  v.classification, v.confidence, v.attack_type, v.reasoning, v.cited_hunk, v.model
           FROM releases r JOIN verdicts v ON v.release_id = r.id
           WHERE r.stage IN ('needs_adjudication', 'refused_to_extract', 'refused_to_fetch')
             AND v.human_label IS NULL
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

def get_cursor(conn):
    row = conn.execute("SELECT last_serial, updated_at FROM cursor WHERE id=1").fetchone()
    return dict(row) if row else None

def count_releases(conn) -> int:
    return conn.execute("SELECT COUNT(*) FROM releases").fetchone()[0]

def all_verdicts(conn):
    return conn.execute(
        """SELECT r.id AS release_id, r.package, r.version, r.prior_version,
                  r.is_first_release, r.triage_score,
                  v.classification, v.confidence, v.attack_type, v.reasoning,
                  v.cited_hunk, v.model, v.urgent, v.created_at, v.human_label
           FROM releases r JOIN verdicts v ON v.release_id = r.id
           ORDER BY CASE v.classification WHEN 'malicious' THEN 0
                    WHEN 'suspicious' THEN 1 ELSE 2 END, r.id DESC""").fetchall()
