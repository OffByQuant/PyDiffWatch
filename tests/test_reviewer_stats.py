# tests/test_reviewer_stats.py
import dataclasses

from pydiffwatch import store
from pydiffwatch.config import Config


def test_stats_roundtrip_and_upsert(tmp_path):
    cfg = dataclasses.replace(Config(), db_path=tmp_path / "db.sqlite")
    conn = store.connect(cfg); store.init_schema(conn)
    assert store.get_reviewer_stats(conn, "http://h/v1", "m") is None
    kw = dict(tok_s=85.0, chars_per_token=3.4, samples=1, state="closed", detail="", paused_until=0.0, slow_streak=0)
    store.save_reviewer_stats(conn, "http://h/v1", "m", **kw)
    store.save_reviewer_stats(conn, "http://h/v1", "m", **{**kw, "samples": 2, "state": "open"})
    s = store.get_reviewer_stats(conn, "http://h/v1", "m")
    assert s["samples"] == 2 and s["state"] == "open" and s["tok_s"] == 85.0
    assert store.get_reviewer_stats(conn, "http://h/v1", "other-model") is None
