import json
import pytest
from pydiffwatch import store
from pydiffwatch.config import Config

@pytest.fixture
def conn(tmp_path):
    cfg = Config(db_path=tmp_path / "db.sqlite")
    c = store.connect(cfg); store.init_schema(c)
    yield c
    c.close()

def test_cursor_roundtrip(conn):
    assert store.get_last_serial(conn) == 0
    store.set_last_serial(conn, 42)
    assert store.get_last_serial(conn) == 42

def test_release_unique(conn):
    rid1 = store.record_release(conn, "pkg", "1.0", 1, False, None, "sdist")
    rid2 = store.record_release(conn, "pkg", "1.0", 1, False, None, "sdist")
    assert rid1 == rid2  # INSERT OR IGNORE returns existing row id
    assert store.release_exists(conn, "pkg", "1.0")

def test_alert_dedupe(conn):
    rid = store.record_release(conn, "pkg", "1.1", 2, False, "1.0", "sdist")
    k = "pkg|1.1|suspicious-heuristic"
    assert store.record_alert(conn, rid, "suspicious-heuristic", 55.0, "[]", k) is True
    assert store.record_alert(conn, rid, "suspicious-heuristic", 55.0, "[]", k) is False  # deduped

def test_prior_version(conn):
    store.record_release(conn, "pkg", "1.0", 1, False, None, "sdist")
    store.record_release(conn, "pkg", "1.1", 2, False, "1.0", "sdist")
    assert store.prior_version(conn, "pkg", "1.2") == "1.1"
    assert store.prior_version(conn, "newpkg", "1.0") is None

def test_update_stage_partial(conn):
    rid = store.record_release(conn, "pkg", "1.0", 1, False, None, "sdist")
    store.update_stage(conn, rid, "triaged", 55.0, '["r"]')
    store.update_stage(conn, rid, "alerted")  # stage-only must NOT clobber score/rules
    row = conn.execute(
        "SELECT stage, triage_score, triage_rules FROM releases WHERE id=?", (rid,)
    ).fetchone()
    assert row[0] == "alerted" and row[1] == 55.0 and row[2] == '["r"]'

def test_init_schema_idempotent(tmp_path):
    from pydiffwatch.config import Config
    cfg = Config(db_path=tmp_path / "db.sqlite")
    c = store.connect(cfg)
    store.init_schema(c); store.init_schema(c)  # running twice must not error
    assert store.get_last_serial(c) == 0
    c.close()

def test_migration_adds_maintainer_column_idempotent(tmp_path):
    # A DB created before maintainer_metadata existed (the production .sqlite) must gain the column
    # via ALTER without losing existing rows — and re-running init_schema must be a no-op.
    cfg = Config(db_path=tmp_path / "old.sqlite")
    c = store.connect(cfg)
    c.executescript(
        """CREATE TABLE releases(id INTEGER PRIMARY KEY, package TEXT, version TEXT, serial INTEGER,
           is_first_release INTEGER, prior_version TEXT, artifact_basis TEXT, triage_score REAL,
           triage_rules TEXT, stage TEXT, processed_at TEXT, UNIQUE(package, version));""")
    c.execute("INSERT INTO releases(package, version, serial) VALUES('old', '1.0', 1)"); c.commit()
    store.init_schema(c); store.init_schema(c)            # migrate; second call must not error
    cols = {r[1] for r in c.execute("PRAGMA table_info(releases)")}
    assert "maintainer_metadata" in cols
    row = c.execute("SELECT package, maintainer_metadata FROM releases WHERE version='1.0'").fetchone()
    assert row[0] == "old" and row[1] is None            # pre-existing row survived; new column NULL
    c.close()

def test_release_metadata_roundtrip(conn):
    rid = store.record_release(conn, "pkg", "2.0", 7, False, "1.0", "sdist")
    meta = {"author": "alice", "maintainer": None, "roles": ["alice"], "upload_time": "2026-01-01T00:00:00Z"}
    store.update_release_metadata(conn, rid, json.dumps(meta))
    assert store.get_release_metadata(conn, "pkg", "2.0") == meta
    assert store.get_release_metadata(conn, "pkg", "9.9") is None   # missing row -> None

def test_evidence_roundtrip(conn):
    rid = store.record_release(conn, "pkg", "3.0", 9, False, "2.0", "sdist")
    assert conn.execute("SELECT evidence FROM releases WHERE id=?", (rid,)).fetchone()[0] is None
    store.update_evidence(conn, rid, "--- file: setup.py (modified) ---\n+ os.system('id')")
    assert conn.execute("SELECT evidence FROM releases WHERE id=?",
                        (rid,)).fetchone()[0] == "--- file: setup.py (modified) ---\n+ os.system('id')"

def test_migration_adds_evidence_column_idempotent(tmp_path):
    # A DB created before the evidence column existed (the production .sqlite) must gain it via ALTER
    # without losing rows; re-running init_schema must be a no-op.
    cfg = Config(db_path=tmp_path / "old.sqlite")
    c = store.connect(cfg)
    c.executescript(
        """CREATE TABLE releases(id INTEGER PRIMARY KEY, package TEXT, version TEXT, serial INTEGER,
           is_first_release INTEGER, prior_version TEXT, artifact_basis TEXT, triage_score REAL,
           triage_rules TEXT, stage TEXT, processed_at TEXT, UNIQUE(package, version));""")
    c.execute("INSERT INTO releases(package, version, serial) VALUES('old', '1.0', 1)"); c.commit()
    store.init_schema(c); store.init_schema(c)
    cols = {r[1] for r in c.execute("PRAGMA table_info(releases)")}
    assert "evidence" in cols
    row = c.execute("SELECT package, evidence FROM releases WHERE version='1.0'").fetchone()
    assert row[0] == "old" and row[1] is None
    c.close()

def test_record_verdict_inserts_and_is_idempotent_per_release(tmp_path):
    from pydiffwatch.config import Config
    from pydiffwatch import store
    from pydiffwatch.models import Verdict
    cfg = Config(db_path=tmp_path / "d.sqlite")
    conn = store.connect(cfg); store.init_schema(conn)
    rid = store.record_release(conn, "pkg", "1.0", 5, True, None, "sdist")
    v = Verdict("pkg", "1.0", "malicious", 80.0, [], True,
                confidence=0.9, attack_type="install-hook-rce",
                reasoning="why", cited_hunk="setup.py:1-3",
                recommended_action="report-to-pypi", model="claude-sonnet-4-6")
    store.record_verdict(conn, rid, v)
    row = conn.execute("SELECT classification, confidence, model FROM verdicts WHERE release_id=?",
                       (rid,)).fetchone()
    assert row["classification"] == "malicious" and row["model"] == "claude-sonnet-4-6"
    # re-review (escalation) replaces, does not duplicate
    v2 = Verdict("pkg", "1.0", "malicious", 80.0, [], True, confidence=0.97,
                 attack_type="install-hook-rce", reasoning="why2", cited_hunk="setup.py:1-3",
                 recommended_action="report-to-pypi", model="claude-opus-4-8")
    store.record_verdict(conn, rid, v2)
    rows = conn.execute("SELECT confidence, model FROM verdicts WHERE release_id=?", (rid,)).fetchall()
    assert len(rows) == 1 and rows[0]["model"] == "claude-opus-4-8" and rows[0]["confidence"] == 0.97
