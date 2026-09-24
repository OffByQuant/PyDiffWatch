"""A release the fetcher refused (an sdist it would not unpack, or a download over the size cap) was never
looked at. Oversized or malformed archives can hide a payload from scanners, so the release is not
dropped: the alert says why it was refused, and it waits in `pending` for a manual review."""
from pydiffwatch import fetcher, notifier, orchestrator, store
from pydiffwatch.models import NewRelease


def _refuse(cfg, exc, capsys):
    conn = store.connect(cfg); store.init_schema(conn)
    rel = NewRelease("big-native-pkg", "0.1.0", 7)
    orchestrator._process_fetched(cfg, conn, None, None, rel, exc)
    return conn, capsys.readouterr().out


def test_refused_extract_alert_names_the_reason_and_asks_for_a_manual_review(tmp_cfg, capsys):
    _, out = _refuse(tmp_cfg, fetcher.RefusedToExtract("decompressed-size"), capsys)
    assert "big-native-pkg 0.1.0" in out
    assert "decompressed-size" in out and "manual review" in out and "UNREVIEWED" in out


def test_size_refusal_alerts_with_its_reason(tmp_cfg, capsys):
    conn, out = _refuse(tmp_cfg, fetcher.RefusedToFetch("download-size"), capsys)
    assert store.get_stage(conn, "big-native-pkg", "0.1.0") == "refused_to_fetch"
    assert "big-native-pkg 0.1.0" in out and "download-size" in out and "manual review" in out


def test_refused_release_waits_in_pending_without_a_refetch(tmp_cfg, capsys, monkeypatch):
    conn, _ = _refuse(tmp_cfg, fetcher.RefusedToExtract("members"), capsys)
    assert store.get_stage(conn, "big-native-pkg", "0.1.0") == "refused_to_extract"
    monkeypatch.setattr(fetcher, "fetch_artifacts", lambda *a: (_ for _ in ()).throw(AssertionError("refetched")))
    [item] = orchestrator.list_pending(tmp_cfg)
    assert item["package"] == "big-native-pkg" and "manual review" in item["reasoning"]
    assert "members" in item["reasoning"] and item["diff_text"] is None and "refused" in item["fetch_error"]


def test_size_refused_release_waits_in_pending(tmp_cfg, capsys, monkeypatch):
    _refuse(tmp_cfg, fetcher.RefusedToFetch("download-size"), capsys)
    monkeypatch.setattr(fetcher, "fetch_artifacts", lambda *a: (_ for _ in ()).throw(AssertionError("refetched")))
    [item] = orchestrator.list_pending(tmp_cfg)
    assert "download-size" in item["reasoning"] and "refused" in item["fetch_error"]


def test_refused_release_can_be_adjudicated(tmp_cfg, capsys, monkeypatch):
    conn, _ = _refuse(tmp_cfg, fetcher.RefusedToExtract("total-size"), capsys)
    monkeypatch.setattr(notifier, "post_webhook", lambda *a: True)
    rid = conn.execute("SELECT id FROM releases").fetchone()[0]
    assert len(orchestrator.list_pending(tmp_cfg)) == 1
    assert orchestrator.adjudicate(tmp_cfg, rid, "benign")["label"] == "benign"
    assert orchestrator.list_pending(tmp_cfg) == []
