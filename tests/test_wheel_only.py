"""Wheel-only releases (spec §2 decision 3, U4). pydiffwatch scans sdists only, so a package that switches to
wheel-only could ship a payload no scan sees: that switch warns once and waits in `pending`. A package that has
always been wheel-only stays silent.

Wheels often upload before the sdist (split CI jobs), so a switch is not warned at once: the release waits off the
cursor (`no_sdist_wait`) for `wheel_only_grace_minutes`, then is re-fetched. An sdist by then is scanned normally
with no alert; only a release still wheel-only after the grace warns. The changelog's sdist upload event is the
fast path: it re-scans a waiting or no_sdist release at once."""
import dataclasses
import email.message
import json

from pydiffwatch import fetcher, ingest, orchestrator, store
from pydiffwatch.config import Config
from pydiffwatch.models import NewRelease
from tests.fixtures.build_fixtures import make_sdist

SW = [("1.0", "2026-01-01T00:00:00Z", True), ("1.1", "2026-02-01T00:00:00Z", False)]    # 1.1 switched
BOTH = [("1.0", "2026-01-01T00:00:00Z", True), ("1.1", "2026-02-01T00:00:00Z", True)]   # 1.1's sdist is up


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
    monkeypatch.setattr(ingest, "changes_since", lambda cfg, since, **kw: [r for r in events if r.serial > since])


def _idx(entries, meta_serial):
    """/simple/ body: entries = [(serial, name), ...]."""
    return json.dumps({"meta": {"_last-serial": meta_serial, "api-version": "1.4"},
                       "projects": [{"_last-serial": s, "name": n} for s, n in entries]}).encode()


def _hdrs2(**kv):
    m = email.message.Message()
    for k, v in kv.items():
        m[k.replace("_", "-")] = v
    return m


def _pjbody(name, serial, meta):
    """A /pypi/<name>/json body built from a `_meta(name, versions)` dict."""
    return json.dumps({"info": {"name": name}, "last_serial": serial, "releases": meta["releases"]}).encode()


def _ingest_serve(monkeypatch, index, projects):
    """The real ingest.changes_since over a stubbed ingest._get. index: /simple/ body bytes; projects:
    {name: (header_serial, body_bytes)}."""
    def fake_get(cfg_, url, headers, limit, deadline):
        if url.endswith("/simple/"):
            return 200, _hdrs2(), index
        name = url.split("/pypi/")[1].split("/json")[0]
        serial, body = projects[name]
        return 200, _hdrs2(X_PyPI_Last_Serial=str(serial)), body
    monkeypatch.setattr(ingest, "_get", fake_get)


def _alerts(conn, package):
    return conn.execute("SELECT a.dedupe_key FROM alerts a JOIN releases r ON r.id = a.release_id "
                        "WHERE r.package=?", (package,)).fetchall()


def _grace_over(conn):
    conn.execute("UPDATE releases SET recheck_at=0 WHERE stage='no_sdist_wait'"); conn.commit()


def _switch_alerted(cfg, monkeypatch, capsys, pkg="sw", metas=None):
    """Tick 1 parks the switched release; the grace runs out; tick 2's re-check (still wheel-only) warns."""
    metas = metas if metas is not None else {pkg: _meta(pkg, SW)}
    _pypi(monkeypatch, metas)
    _feed(monkeypatch, [NewRelease(pkg, "1.1", 10)])
    orchestrator.run_once(cfg, seed_if_fresh=False)
    conn = store.connect(cfg)
    assert store.get_stage(conn, pkg, "1.1") == "no_sdist_wait" and _alerts(conn, pkg) == []
    _grace_over(conn)
    orchestrator.run_once(cfg, seed_if_fresh=False)
    return conn


# --- the switch ------------------------------------------------------------------------------------------

def test_the_fetcher_names_the_sdist_release_a_wheel_only_one_switched_from(monkeypatch):
    metas = {"sw": _meta("sw", SW + [("1.2", "2026-03-01T00:00:00Z", False)]),
             "wo": _meta("wo", [("1.0", "2026-01-01T00:00:00Z", False), ("1.1", "2026-02-01T00:00:00Z", False)])}
    _pypi(monkeypatch, metas)
    got = fetcher.fetch_artifacts(Config(), NewRelease("sw", "1.1", 5))
    assert isinstance(got, fetcher.NoSdist) and got.switched_from == "1.0"
    assert fetcher.fetch_artifacts(Config(), NewRelease("sw", "1.2", 6)).switched_from is None  # already switched
    assert fetcher.fetch_artifacts(Config(), NewRelease("wo", "1.1", 7)).switched_from is None  # always wheel-only
    assert fetcher.fetch_artifacts(Config(), NewRelease("wo", "1.0", 8)).switched_from is None  # first release


def test_a_switch_still_wheel_only_after_the_grace_warns_once_and_waits_in_pending(tmp_cfg, monkeypatch, capsys):
    conn = _switch_alerted(tmp_cfg, monkeypatch, capsys)
    out = capsys.readouterr().out
    assert "sw 1.1" in out and "switched to wheel-only" in out and "1.0" in out
    assert "UNREVIEWED:" in out and "Not scanned. Needs manual review." in out
    assert store.get_stage(conn, "sw", "1.1") == "no_sdist" and store.get_last_serial(conn) == 10
    [item] = orchestrator.list_pending(tmp_cfg)
    assert item["package"] == "sw" and item["not_scanned"] == "no_sdist"
    assert "switched to wheel-only" in item["reasoning"]
    _feed(monkeypatch, [NewRelease("sw", "1.1", 10), NewRelease("sw", "1.1", 11)])   # a re-tick
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    assert capsys.readouterr().out == "" and len(_alerts(conn, "sw")) == 1


def test_a_split_ci_release_whose_sdist_lands_within_the_grace_never_alerts(tmp_cfg, monkeypatch, capsys):
    metas = {"sw": _meta("sw", SW)}
    _pypi(monkeypatch, metas)
    _feed(monkeypatch, [NewRelease("sw", "1.1", 10)])
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)                   # wheels first: waits
    conn = store.connect(tmp_cfg)
    assert store.get_stage(conn, "sw", "1.1") == "no_sdist_wait" and store.get_last_serial(conn) == 10
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)                   # grace not over: not re-fetched
    assert store.get_stage(conn, "sw", "1.1") == "no_sdist_wait"
    metas["sw"] = _meta("sw", BOTH)
    _grace_over(conn)
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)                   # the due re-check finds the sdist
    assert store.get_stage(conn, "sw", "1.1") == "triaged"
    assert capsys.readouterr().out == "" and _alerts(conn, "sw") == [] and orchestrator.list_pending(tmp_cfg) == []


def test_an_always_wheel_only_package_stays_silent(tmp_cfg, monkeypatch, capsys):
    _pypi(monkeypatch, {"wo": _meta("wo", [("1.0", "2026-01-01T00:00:00Z", False),
                                           ("1.1", "2026-02-01T00:00:00Z", False)])})
    _feed(monkeypatch, [NewRelease("wo", "1.0", 10), NewRelease("wo", "1.1", 11)])
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    conn = store.connect(tmp_cfg)
    assert capsys.readouterr().out == "" and _alerts(conn, "wo") == []
    assert store.get_stage(conn, "wo", "1.1") == "no_sdist" and orchestrator.list_pending(tmp_cfg) == []


def test_the_store_sees_a_switch_when_the_previous_sdist_was_deleted_from_pypi(tmp_cfg, monkeypatch, capsys):
    # We scanned 1.1's sdist; its owner then deleted it, so the JSON alone shows 1.1 as wheel-only too.
    m = _meta("del", [("1.0", "2026-01-01T00:00:00Z", True), ("1.1", "2026-02-01T00:00:00Z", True),
                      ("2.0", "2026-03-01T00:00:00Z", False)])
    m["releases"]["1.1"] = [f for f in m["releases"]["1.1"] if f["packagetype"] != "sdist"]
    assert fetcher._switched_from(m["releases"], "2.0") is None
    conn = store.connect(tmp_cfg); store.init_schema(conn)
    rid = store.record_release(conn, "del", "1.1", 5, False, "1.0", "sdist")
    store.update_stage(conn, rid, "triaged")
    _pypi(monkeypatch, {"del": m})
    _feed(monkeypatch, [NewRelease("del", "2.0", 10)])
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    assert store.get_stage(conn, "del", "2.0") == "no_sdist_wait"
    _grace_over(conn)
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    out = capsys.readouterr().out
    assert "switched to wheel-only" in out and "1.1" in out and len(_alerts(conn, "del")) == 1


def test_prune_keeps_the_waiting_and_the_switch_rows(tmp_cfg, monkeypatch, capsys):
    conn = _switch_alerted(tmp_cfg, monkeypatch, capsys)                  # sw 1.1: no_sdist, with the warning
    _pypi(monkeypatch, {"sw": _meta("sw", SW), "wt": _meta("wt", SW)})
    orchestrator._process_fetched(tmp_cfg, conn, None, None, NewRelease("wt", "1.1", 11),
                                  fetcher.download(tmp_cfg, NewRelease("wt", "1.1", 11)))
    assert store.get_stage(conn, "wt", "1.1") == "no_sdist_wait"
    for pkg in ("sw", "wt"):                                              # so 1.1 is not the newest
        store.record_release(conn, pkg, "9.9", 99, False, None, "sdist")
    conn.execute("UPDATE releases SET processed_at='2000-01-01T00:00:00+00:00' WHERE version != '9.9'")
    conn.commit()
    store.prune(conn, retention_days=1)
    assert store.get_stage(conn, "sw", "1.1") == "no_sdist"
    assert store.get_stage(conn, "wt", "1.1") == "no_sdist_wait"


# --- the upload race -------------------------------------------------------------------------------------

def test_a_merged_release_is_not_lost_when_the_per_run_cap_cuts_its_sdist_event(tmp_cfg, monkeypatch):
    # Real ingest.changes_since (Task 3) over a stubbed simple index / project JSON, floor unset (backfill
    # default): every unseen version counts as new. max_releases_per_run cuts the first poll to 3 of the 4
    # projects; the cursor's ceiling holds below the cut one, so the second tick picks it up.
    pkgs = ["x-demo", "a-demo", "b-demo", "c-demo"]
    metas = {p: _meta(p, [("1.0", "2026-01-01T00:00:00Z", True)]) for p in pkgs}
    _pypi(monkeypatch, metas)
    entries = [(10, "x-demo"), (11, "a-demo"), (12, "b-demo"), (13, "c-demo")]
    projects = {name: (serial, _pjbody(name, serial, metas[name])) for serial, name in entries}
    _ingest_serve(monkeypatch, _idx(entries, 13), projects)
    cfg = dataclasses.replace(tmp_cfg, max_releases_per_run=3)
    orchestrator.run_once(cfg, seed_if_fresh=False)
    orchestrator.run_once(cfg, seed_if_fresh=False)
    conn = store.connect(cfg)
    assert {p: store.get_stage(conn, p, "1.0") for p in pkgs} == dict.fromkeys(pkgs, "triaged")
    assert store.get_last_serial(conn) == 13


def test_a_later_sdist_upload_rescans_a_wheel_first_release_at_once(tmp_cfg, monkeypatch, capsys):
    metas = {"race": _meta("race", SW)}
    _pypi(monkeypatch, metas)
    _feed(monkeypatch, [NewRelease("race", "1.1", 10)])
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)                   # the wheels came first: waits
    metas["race"] = _meta("race", BOTH)
    _feed(monkeypatch, [NewRelease("race", "1.1", 10),
                        NewRelease("race", "1.1", 20, new_release=False, sdist_upload=True)])
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)                   # the fast path, inside the grace
    conn = store.connect(tmp_cfg)
    row = conn.execute("SELECT stage, prior_version FROM releases WHERE package='race' AND version='1.1'").fetchone()
    assert tuple(row) == ("triaged", "1.0")                              # scanned normally, against 1.0
    assert store.get_last_serial(conn) == 20
    assert capsys.readouterr().out == "" and orchestrator.list_pending(tmp_cfg) == []


def test_a_late_sdist_after_the_warning_rescans_and_clears_it(tmp_cfg, monkeypatch, capsys):
    metas = {"race": _meta("race", SW)}
    conn = _switch_alerted(tmp_cfg, monkeypatch, capsys, pkg="race", metas=metas)
    assert store.get_stage(conn, "race", "1.1") == "no_sdist"
    metas["race"] = _meta("race", BOTH)
    _feed(monkeypatch, [NewRelease("race", "1.1", 20, new_release=False, sdist_upload=True)])
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    assert store.get_stage(conn, "race", "1.1") == "triaged"
    assert orchestrator.list_pending(tmp_cfg) == []                       # no stale switch warning
    assert conn.execute("SELECT count(*) FROM verdicts").fetchone()[0] == 0


def test_a_stale_json_on_the_merged_sdist_event_is_rescanned_when_due(tmp_cfg, monkeypatch, capsys):
    # The poll's project JSON is still wheel-only (SW): the wheel-only release parks in no_sdist_wait, off
    # the cursor. Its rescan, once the grace is over, goes through the retry sweep (_retry_metadata), not
    # ingest, so PyPI's JSON catching up is modeled purely via the fetcher stub.
    metas = {"r-demo": _meta("r-demo", SW)}
    _pypi(monkeypatch, metas)
    entries = [(10, "r-demo")]
    projects = {"r-demo": (10, _pjbody("r-demo", 10, metas["r-demo"]))}
    _ingest_serve(monkeypatch, _idx(entries, 10), projects)
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    conn = store.connect(tmp_cfg)
    assert store.get_stage(conn, "r-demo", "1.1") == "no_sdist_wait"
    metas["r-demo"] = _meta("r-demo", BOTH)
    _grace_over(conn)
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    assert store.get_stage(conn, "r-demo", "1.1") == "triaged" and _alerts(conn, "r-demo") == []


def test_an_sdist_upload_for_a_release_that_was_never_no_sdist_fetches_nothing(tmp_cfg, monkeypatch, request):
    _pypi(monkeypatch, {"n": _meta("n", BOTH)})
    _feed(monkeypatch, [NewRelease("n", "1.1", 10)])
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)   # a real fetch + extract, before scan_stub patches extract_download
    conn = store.connect(tmp_cfg)
    assert store.get_stage(conn, "n", "1.1") == "triaged"
    scan_stub = request.getfixturevalue("scan_stub")   # only now: guard the next fetch without touching the real one above
    scan_stub.fetch(lambda *a, **k: (_ for _ in ()).throw(AssertionError("refetched")))
    _feed(monkeypatch, [NewRelease("n", "1.1", 11, new_release=False, sdist_upload=True),     # its own sdist upload
                        NewRelease("unseen", "2.0", 12, new_release=False, sdist_upload=True)])  # never recorded
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    assert store.get_last_serial(conn) == 12
    assert store.get_stage(conn, "unseen", "2.0") is None


def test_waiting_and_failed_rescans_never_pin_the_cursor(tmp_cfg, monkeypatch):
    metas = {"race": _meta("race", SW), "later": _meta("later", BOTH)}
    _pypi(monkeypatch, metas)
    _feed(monkeypatch, [NewRelease("race", "1.1", 10), NewRelease("later", "1.1", 11)])
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    conn = store.connect(tmp_cfg)
    assert store.get_stage(conn, "race", "1.1") == "no_sdist_wait" and store.get_last_serial(conn) == 11

    def down(pkg, cfg):
        raise fetcher.MetadataUnavailable("HTTP 503")
    monkeypatch.setattr(fetcher, "_package_json", down)
    _feed(monkeypatch, [NewRelease("race", "1.1", 20, new_release=False, sdist_upload=True),
                        NewRelease("other", "1.0", 21)])
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    assert store.get_last_serial(conn) == 21
    assert store.get_stage(conn, "race", "1.1") == "metadata_retry"     # retried off the cursor, then gave_up


def test_a_rescan_keeps_a_persons_label_on_the_switch_warning(tmp_cfg, monkeypatch, capsys):
    metas = {"race": _meta("race", SW)}
    conn = _switch_alerted(tmp_cfg, monkeypatch, capsys, pkg="race", metas=metas)
    rid = conn.execute("SELECT id FROM releases WHERE package='race'").fetchone()[0]
    store.adjudicate(conn, rid, "malicious", "payload in the wheel")
    metas["race"] = _meta("race", BOTH)
    _feed(monkeypatch, [NewRelease("race", "1.1", 20, new_release=False, sdist_upload=True)])
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    assert store.get_stage(conn, "race", "1.1") == "triaged"
    assert conn.execute("SELECT human_label FROM verdicts WHERE release_id=?", (rid,)).fetchone()[0] == "malicious"


# --- Task 8 ----------------------------------------------------------------------------------------------

def test_parking_in_the_wait_logs_once_with_the_due_time(tmp_cfg, caplog):
    # (e): an operator can see why a release went quiet, and when it will be decided.
    import datetime, logging
    conn = store.connect(tmp_cfg); store.init_schema(conn)
    rel = NewRelease("sw", "1.1", 10)
    with caplog.at_level(logging.INFO, logger="pydiffwatch.orchestrator"):
        orchestrator._process_fetched(tmp_cfg, conn, None, None, rel, fetcher.NoSdist(switched_from="1.0"))
        orchestrator._process_fetched(tmp_cfg, conn, None, None, rel, fetcher.NoSdist(switched_from="1.0"))
    [rec] = [r for r in caplog.records if "no_sdist_wait" in r.getMessage()]
    assert rec.levelno == logging.INFO
    due = datetime.datetime.fromtimestamp(store.recheck_at(conn, 1), datetime.UTC).isoformat(timespec="seconds")
    assert "sw==1.1" in rec.getMessage() and due in rec.getMessage()


def test_a_due_wait_row_is_not_starved_by_a_backlog_of_failing_retries(tmp_cfg, monkeypatch, scan_stub):
    # (f): 45 older releases keep failing; they used to fill LIMIT 20 (ordered by serial) every tick.
    conn = store.connect(tmp_cfg); store.init_schema(conn)
    for i in range(45):
        rid = store.record_release(conn, f"bad{i}", "1.0", i + 1, False, None, "sdist")
        store.update_stage(conn, rid, "metadata_retry")
    rid = store.record_release(conn, "sw", "1.1", 100, False, None, "sdist")
    store.wait_for_sdist(conn, rid, 0)

    def fetch(cfg, rel, **k):
        if rel.package == "sw":
            return fetcher.NoSdist(switched_from="1.0")
        raise TimeoutError("still down")
    scan_stub.fetch(fetch)
    orchestrator._retry_metadata(tmp_cfg, conn, None, None, False, None)
    assert store.get_stage(conn, "sw", "1.1") == "no_sdist"       # decided on the first tick


def test_the_retry_sweep_stops_at_its_time_budget_and_leaves_the_rest_for_next_tick(tmp_cfg, monkeypatch, scan_stub):
    # Review finding 2: with deadlines x attempt, 40 trickling rows could hold the scan lock for hours before
    # ingest. The sweep stops starting windows once packument_deadline_s has passed; the rest waits a tick.
    # Rows tried most come first (fix round 2), so a row once started reaches gave_up within 4 ticks.
    import threading
    conn = store.connect(tmp_cfg); store.init_schema(conn)
    for i in range(10):
        rid = store.record_release(conn, f"bad{i}", "1.0", i + 1, False, None, "sdist")
        store.update_stage(conn, rid, "metadata_retry")
    clock, lock = [0.0], threading.Lock()

    def fetch(cfg, rel, **k):
        with lock:
            clock[0] += 200.0                      # each fetch trickles for 200 s
        raise TimeoutError("trickling")
    scan_stub.fetch(fetch)

    def attempts():
        return sorted(r[0] for r in conn.execute("SELECT fetch_attempts FROM releases"))
    W = tmp_cfg.fetch_concurrency
    orchestrator._retry_metadata(tmp_cfg, conn, None, None, False, None, clock=lambda: clock[0])
    assert attempts() == [0] * (10 - W) + [1] * W          # one window (800 s > 300 s budget), then stop
    clock[0] = 0.0
    orchestrator._retry_metadata(tmp_cfg, conn, None, None, False, None, clock=lambda: clock[0])
    assert attempts() == [0] * (10 - W) + [2] * W          # next tick: the most-tried rows go first


def test_a_steady_inflow_of_new_failures_does_not_starve_older_retries(tmp_cfg, monkeypatch, scan_stub):
    # Fix round 2 (the reviewer's scratch test): least-tried-first kept every new failure (attempt 1) ahead of
    # older rows, so under a steady inflow the older rows were never retried, never gave up and never alerted.
    import threading
    conn = store.connect(tmp_cfg); store.init_schema(conn)
    W = tmp_cfg.fetch_concurrency
    old = []
    for i in range(4):
        rid = store.record_release(conn, f"old{i}", "1.0", i + 1, False, None, "sdist")
        store.update_stage(conn, rid, "metadata_retry")
        conn.execute("UPDATE releases SET fetch_attempts=2 WHERE id=?", (rid,)); conn.commit()
        old.append(rid)
    clock, lock = [0.0], threading.Lock()

    def fetch(cfg, rel, **k):
        with lock:
            clock[0] += 200.0
        raise TimeoutError("trickling")
    scan_stub.fetch(fetch)
    serial = 100
    for tick in range(30):
        for j in range(W):            # this tick's ingest: W new releases fail -> metadata_retry at attempt 1
            serial += 1
            rid = store.record_release(conn, f"new{serial}", "1.0", serial, False, None, "sdist")
            store.note_metadata_failure(conn, rid, "TimeoutError")
        clock[0] = 0.0
        orchestrator._retry_metadata(tmp_cfg, conn, None, None, False, None, clock=lambda: clock[0])
    olds = [tuple(conn.execute("SELECT stage, fetch_attempts FROM releases WHERE id=?", (r,)).fetchone())
            for r in old]
    assert olds == [("gave_up", store.METADATA_ATTEMPTS)] * 4
    assert conn.execute("SELECT COUNT(*) FROM releases WHERE stage='gave_up'").fetchone()[0] > 4


def test_a_previous_release_refused_for_its_download_size_counts_as_one_that_shipped_an_sdist(tmp_cfg):
    # A download refused for size proves there was an sdist to download: a wheel-only next release is a switch.
    conn = store.connect(tmp_cfg); store.init_schema(conn)
    rid = store.record_release(conn, "huge", "1.0", 5, False, None, "sdist")
    store.update_stage(conn, rid, "refused_to_fetch")
    store.record_release(conn, "huge", "1.1", 6, False, None, "sdist")
    assert store.previous_sdist_release(conn, "huge", "1.1") == "1.0"
