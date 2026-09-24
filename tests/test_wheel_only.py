"""Wheel-only releases (spec §2 decision 3, U4). pydiffwatch scans sdists only, so a package that switches to
wheel-only could ship a payload no scan sees: that switch warns once and waits in `pending`. A package that has
always been wheel-only stays silent. When the wheels upload before the sdist, the later sdist upload (a separate
changelog event) re-processes the release, which is then scanned normally."""
from pydiffwatch import fetcher, ingest, orchestrator, store
from pydiffwatch.config import Config
from pydiffwatch.models import NewRelease
from tests.fixtures.build_fixtures import make_sdist


def _meta(pkg, versions):
    """versions: (ver, iso_ts, has_sdist). Every release also ships a wheel."""
    releases = {}
    for ver, ts, has_sdist in versions:
        files = [{"packagetype": "bdist_wheel", "url": f"mock://{pkg}/{ver}.whl", "upload_time_iso_8601": ts}]
        if has_sdist:
            files.append({"packagetype": "sdist", "url": f"mock://{pkg}/{ver}", "upload_time_iso_8601": ts,
                          "yanked": False})
        releases[ver] = files
    return {"releases": releases}


def _pypi(monkeypatch, metas):
    """PyPI stubbed in memory: package JSON from `metas` (a dict the test may mutate), sdists from make_sdist."""
    monkeypatch.setattr(fetcher, "_package_json", lambda pkg, cfg: metas[pkg])
    monkeypatch.setattr(fetcher, "_download",
                        lambda url, cfg: make_sdist({"lib/__init__.py": f"V = {url!r}\n".encode()}))


def _feed(monkeypatch, events):
    monkeypatch.setattr(ingest, "changes_since", lambda cfg, since: [r for r in events if r.serial > since])


def _alerts(conn, package):
    return conn.execute("SELECT a.dedupe_key FROM alerts a JOIN releases r ON r.id = a.release_id "
                        "WHERE r.package=?", (package,)).fetchall()


# --- the switch ------------------------------------------------------------------------------------------

def test_the_fetcher_names_the_sdist_release_a_wheel_only_one_switched_from(monkeypatch):
    metas = {"sw": _meta("sw", [("1.0", "2026-01-01T00:00:00Z", True), ("1.1", "2026-02-01T00:00:00Z", False),
                                ("1.2", "2026-03-01T00:00:00Z", False)]),
             "wo": _meta("wo", [("1.0", "2026-01-01T00:00:00Z", False), ("1.1", "2026-02-01T00:00:00Z", False)])}
    _pypi(monkeypatch, metas)
    got = fetcher.fetch_artifacts(Config(), NewRelease("sw", "1.1", 5))
    assert isinstance(got, fetcher.NoSdist) and got.switched_from == "1.0"
    assert fetcher.fetch_artifacts(Config(), NewRelease("sw", "1.2", 6)).switched_from is None  # already switched
    assert fetcher.fetch_artifacts(Config(), NewRelease("wo", "1.1", 7)).switched_from is None  # always wheel-only
    assert fetcher.fetch_artifacts(Config(), NewRelease("wo", "1.0", 8)).switched_from is None  # first release


def test_a_switch_to_wheel_only_warns_once_and_waits_in_pending(tmp_cfg, monkeypatch, capsys):
    _pypi(monkeypatch, {"sw": _meta("sw", [("1.0", "2026-01-01T00:00:00Z", True),
                                           ("1.1", "2026-02-01T00:00:00Z", False)])})
    _feed(monkeypatch, [NewRelease("sw", "1.1", 10)])
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    out = capsys.readouterr().out
    assert "sw 1.1" in out and "switched to wheel-only" in out and "1.0" in out
    assert "UNREVIEWED:" in out and "Not scanned. Needs manual review." in out
    conn = store.connect(tmp_cfg)
    assert store.get_stage(conn, "sw", "1.1") == "no_sdist" and store.get_last_serial(conn) == 10
    [item] = orchestrator.list_pending(tmp_cfg)
    assert item["package"] == "sw" and item["not_scanned"] == "no_sdist"
    assert "switched to wheel-only" in item["reasoning"]
    _feed(monkeypatch, [NewRelease("sw", "1.1", 10), NewRelease("sw", "1.1", 11)])   # a re-tick
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    assert capsys.readouterr().out == "" and len(_alerts(conn, "sw")) == 1


def test_an_always_wheel_only_package_stays_silent(tmp_cfg, monkeypatch, capsys):
    _pypi(monkeypatch, {"wo": _meta("wo", [("1.0", "2026-01-01T00:00:00Z", False),
                                           ("1.1", "2026-02-01T00:00:00Z", False)])})
    _feed(monkeypatch, [NewRelease("wo", "1.0", 10), NewRelease("wo", "1.1", 11)])
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    conn = store.connect(tmp_cfg)
    assert capsys.readouterr().out == "" and _alerts(conn, "wo") == []
    assert store.get_stage(conn, "wo", "1.1") == "no_sdist" and orchestrator.list_pending(tmp_cfg) == []


def test_prune_keeps_the_switch_row(tmp_cfg, monkeypatch):
    _pypi(monkeypatch, {"sw": _meta("sw", [("1.0", "2026-01-01T00:00:00Z", True),
                                           ("1.1", "2026-02-01T00:00:00Z", False)])})
    conn = store.connect(tmp_cfg); store.init_schema(conn)
    orchestrator._process_fetched(tmp_cfg, conn, None, None, NewRelease("sw", "1.1", 10),
                                  fetcher.fetch_artifacts(tmp_cfg, NewRelease("sw", "1.1", 10)))
    store.record_release(conn, "sw", "9.9", 99, False, None, "sdist")       # so 1.1 is not the newest
    conn.execute("UPDATE releases SET processed_at='2000-01-01T00:00:00+00:00' WHERE version != '9.9'")
    conn.commit()
    store.prune(conn, retention_days=1)
    assert store.get_stage(conn, "sw", "1.1") == "no_sdist"


# --- the upload race -------------------------------------------------------------------------------------

def test_ingest_carries_sdist_uploads_and_merges_them_with_the_release(monkeypatch):
    rows = [
        ("a", "1.0", 0, "new release", 10),
        ("a", "1.0", 0, "add source file a-1.0.tar.gz", 11),    # same batch as its release: one item
        ("b", "2.0", 0, "add py3 file b-2.0-py3-none-any.whl", 12),  # a wheel upload: ignored
        ("c", "3.0", 0, "add source file c-3.0.tar.gz", 13),    # an sdist upload on its own
    ]

    class FakeProxy:
        def changelog_since_serial(self, since): return [r for r in rows if r[4] > since]
    monkeypatch.setattr(ingest.xmlrpc.client, "ServerProxy", lambda url, **k: FakeProxy())
    out = ingest.changes_since(Config(), since_serial=0)
    assert [(r.package, r.version, r.serial, r.new_release, r.sdist_upload) for r in out] == [
        ("a", "1.0", 11, True, True), ("c", "3.0", 13, False, True)]


def test_a_later_sdist_upload_rescans_a_wheel_first_release_and_clears_the_switch_warning(tmp_cfg, monkeypatch,
                                                                                          capsys):
    metas = {"race": _meta("race", [("1.0", "2026-01-01T00:00:00Z", True), ("1.1", "2026-02-01T00:00:00Z", False)])}
    _pypi(monkeypatch, metas)
    _feed(monkeypatch, [NewRelease("race", "1.1", 10)])
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)                   # the wheels came first
    assert "switched to wheel-only" in capsys.readouterr().out
    metas["race"] = _meta("race", [("1.0", "2026-01-01T00:00:00Z", True), ("1.1", "2026-02-01T00:00:00Z", True)])
    _feed(monkeypatch, [NewRelease("race", "1.1", 10),
                        NewRelease("race", "1.1", 20, new_release=False, sdist_upload=True)])
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    conn = store.connect(tmp_cfg)
    row = conn.execute("SELECT stage, prior_version FROM releases WHERE package='race' AND version='1.1'").fetchone()
    assert tuple(row) == ("triaged", "1.0")                              # scanned normally, against 1.0
    assert store.get_last_serial(conn) == 20
    assert orchestrator.list_pending(tmp_cfg) == []                       # no stale switch warning
    assert conn.execute("SELECT count(*) FROM verdicts").fetchone()[0] == 0


def test_an_sdist_upload_for_a_release_that_was_never_no_sdist_fetches_nothing(tmp_cfg, monkeypatch):
    _pypi(monkeypatch, {"n": _meta("n", [("1.0", "2026-01-01T00:00:00Z", True), ("1.1", "2026-02-01T00:00:00Z", True)])})
    _feed(monkeypatch, [NewRelease("n", "1.1", 10)])
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    conn = store.connect(tmp_cfg)
    assert store.get_stage(conn, "n", "1.1") == "triaged"
    monkeypatch.setattr(fetcher, "fetch_artifacts", lambda *a, **k: (_ for _ in ()).throw(AssertionError("refetched")))
    _feed(monkeypatch, [NewRelease("n", "1.1", 11, new_release=False, sdist_upload=True),     # its own sdist upload
                        NewRelease("unseen", "2.0", 12, new_release=False, sdist_upload=True)])  # never recorded
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    assert store.get_last_serial(conn) == 12
    assert store.get_stage(conn, "unseen", "2.0") is None


def test_a_failed_rescan_after_the_sdist_upload_never_pins_the_cursor(tmp_cfg, monkeypatch):
    metas = {"race": _meta("race", [("1.0", "2026-01-01T00:00:00Z", True), ("1.1", "2026-02-01T00:00:00Z", False)])}
    _pypi(monkeypatch, metas)
    _feed(monkeypatch, [NewRelease("race", "1.1", 10)])
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)

    def down(pkg, cfg):
        raise fetcher.MetadataUnavailable("HTTP 503")
    monkeypatch.setattr(fetcher, "_package_json", down)
    _feed(monkeypatch, [NewRelease("race", "1.1", 20, new_release=False, sdist_upload=True),
                        NewRelease("other", "1.0", 21)])
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    conn = store.connect(tmp_cfg)
    assert store.get_last_serial(conn) == 21
    assert store.get_stage(conn, "race", "1.1") == "metadata_retry"     # retried off the cursor, then gave_up


def test_a_rescan_keeps_a_persons_label_on_the_switch_warning(tmp_cfg, monkeypatch, capsys):
    metas = {"race": _meta("race", [("1.0", "2026-01-01T00:00:00Z", True), ("1.1", "2026-02-01T00:00:00Z", False)])}
    _pypi(monkeypatch, metas)
    _feed(monkeypatch, [NewRelease("race", "1.1", 10)])
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    conn = store.connect(tmp_cfg)
    rid = conn.execute("SELECT id FROM releases WHERE package='race'").fetchone()[0]
    store.adjudicate(conn, rid, "malicious", "payload in the wheel")
    metas["race"] = _meta("race", [("1.0", "2026-01-01T00:00:00Z", True), ("1.1", "2026-02-01T00:00:00Z", True)])
    _feed(monkeypatch, [NewRelease("race", "1.1", 20, new_release=False, sdist_upload=True)])
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    assert store.get_stage(conn, "race", "1.1") == "triaged"
    assert conn.execute("SELECT human_label FROM verdicts WHERE release_id=?", (rid,)).fetchone()[0] == "malicious"
