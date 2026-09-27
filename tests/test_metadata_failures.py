"""A release whose PyPI metadata can't be read must never pin the cursor. PyPI removes malware fast, so a 404
on the JSON metadata is common and terminal: `metadata_gone`, with an alert saying it was removed before it
could be scanned. Any other metadata failure is retried on later ticks (the retry lives on the release row,
since the changelog already named the version) and given up on, visibly, after 3 attempts. A failed
download of the PRIOR sdist diffs against nothing rather than failing the release."""
import sys
import urllib.error

import pytest

from pydiffwatch import fetcher, ingest, orchestrator, store
from pydiffwatch.models import NewRelease
from tests.fixtures.build_fixtures import make_sdist

NEW = make_sdist({"setup.py": b"from setuptools import setup\nsetup(name='victim')\n",
                  "victim/__init__.py": b"VERSION='1.1'\n"})


def _meta(pkg, versions):
    return {"releases": {v: [{"packagetype": "sdist", "url": f"mock://{pkg}/{v}",
                              "upload_time_iso_8601": ts, "yanked": False}] for v, ts in versions}}


_VICTIM = _meta("victim", [("1.0", "2026-01-01T00:00:00Z"), ("1.1", "2026-02-01T00:00:00Z")])


def _http(code):
    def urlopen(url, *a, **k):
        raise urllib.error.HTTPError(url, code, "x", {}, None)
    return urlopen


def _feed(monkeypatch, releases):
    monkeypatch.setattr(ingest, "changes_since", lambda cfg, since: [r for r in releases if r.serial > since])


def test_a_404_on_package_metadata_is_metadata_gone(monkeypatch):
    monkeypatch.setattr(fetcher.urllib.request, "urlopen", _http(404))
    with pytest.raises(fetcher.MetadataGone):
        fetcher.fetch_artifacts(orchestrator.Config(), NewRelease("victim", "1.1", 1))


def test_any_other_metadata_failure_is_metadata_unavailable(monkeypatch):
    monkeypatch.setattr(fetcher.urllib.request, "urlopen", _http(503))
    with pytest.raises(fetcher.MetadataUnavailable):
        fetcher.fetch_artifacts(orchestrator.Config(), NewRelease("victim", "1.1", 1))


def test_a_404_is_terminal_alerts_and_never_pins_the_cursor(tmp_cfg, monkeypatch, capsys):
    _feed(monkeypatch, [NewRelease("gone", "1.0", 10), NewRelease("after", "1.0", 11)])
    monkeypatch.setattr(fetcher.urllib.request, "urlopen", _http(404))
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    conn = store.connect(tmp_cfg)
    assert store.get_stage(conn, "gone", "1.0") == "metadata_gone"
    assert store.get_last_serial(conn) == 11
    alert = conn.execute("SELECT a.classification FROM alerts a JOIN releases r ON r.id=a.release_id "
                         "WHERE r.package='gone'").fetchone()
    assert alert is not None and alert[0] == "suspicious-heuristic"
    assert "removed from PyPI before it could be scanned" in capsys.readouterr().out


def test_a_repeated_5xx_gives_up_after_3_attempts_without_pinning_the_cursor(tmp_cfg, monkeypatch):
    _feed(monkeypatch, [NewRelease("flaky", "1.0", 10), NewRelease("after", "1.0", 11)])
    calls = []

    def pkg_json(pkg, cfg):
        calls.append(pkg)
        if pkg == "flaky":
            raise urllib.error.HTTPError("u", 503, "x", {}, None)
        return _meta(pkg, [("1.0", "2026-01-01T00:00:00Z")])
    monkeypatch.setattr(fetcher, "_package_json", pkg_json)
    monkeypatch.setattr(fetcher, "_download", lambda url, cfg: NEW)
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    conn = store.connect(tmp_cfg)
    assert store.get_last_serial(conn) == 11                 # one bad release can't hold the cursor
    assert store.get_stage(conn, "flaky", "1.0") == "metadata_retry"
    assert store.metadata_retry_counts(conn) == {"retrying": 1, "gave_up": 0}
    for _ in range(2):                                       # the feed has nothing new; the retry queue does
        orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    assert calls.count("flaky") == 3
    assert store.get_stage(conn, "flaky", "1.0") == "gave_up"
    assert store.metadata_retry_counts(conn) == {"retrying": 0, "gave_up": 1}
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    assert calls.count("flaky") == 3                         # given up: not fetched again
    assert orchestrator.metadata_retry_counts(tmp_cfg) == {"retrying": 0, "gave_up": 1, "oldest_retrying_age": None}


def test_a_retried_release_is_scanned_once_metadata_comes_back(tmp_cfg, monkeypatch):
    _feed(monkeypatch, [NewRelease("victim", "1.1", 10)])
    state = {"fail": True}

    def pkg_json(pkg, cfg):
        if state["fail"]:
            raise TimeoutError("download took longer than 300s")
        return _VICTIM
    monkeypatch.setattr(fetcher, "_package_json", pkg_json)
    monkeypatch.setattr(fetcher, "_download", lambda url, cfg: NEW)
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    state["fail"] = False
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    conn = store.connect(tmp_cfg)
    assert store.get_stage(conn, "victim", "1.1") == "triaged"
    assert store.metadata_retry_counts(conn) == {"retrying": 0, "gave_up": 0}


def test_a_failed_prior_sdist_download_diffs_against_nothing(monkeypatch):
    monkeypatch.setattr(fetcher, "_package_json", lambda pkg, cfg: _VICTIM)

    def download(url, cfg):
        if url.endswith("/1.0"):
            raise TimeoutError("download took longer than 120s")     # the prior hung
        return NEW
    monkeypatch.setattr(fetcher, "_download", download)
    art = fetcher.fetch_artifacts(orchestrator.Config(), NewRelease("victim", "1.1", 1))
    assert art.prior_version == "1.0" and art.prior_files == {} and not art.is_new_package
    assert set(art.new_files) == {"setup.py", "victim/__init__.py"}   # every file reported, not just surface
    assert "1.0" in art.prior_error and "TimeoutError" in art.prior_error


def test_a_failed_prior_sdist_is_noted_on_the_release_not_a_fetch_failure(tmp_cfg, monkeypatch):
    _feed(monkeypatch, [NewRelease("victim", "1.1", 10)])
    monkeypatch.setattr(fetcher, "_package_json", lambda pkg, cfg: _VICTIM)

    def download(url, cfg):
        if url.endswith("/1.0"):
            raise urllib.error.URLError("connection reset")
        return NEW
    monkeypatch.setattr(fetcher, "_download", download)
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    conn = store.connect(tmp_cfg)
    row = conn.execute("SELECT stage, fetch_note FROM releases WHERE package='victim'").fetchone()
    assert row["stage"] == "triaged" and "1.0" in row["fetch_note"]
    assert store.get_last_serial(conn) == 10


def test_pending_shows_metadata_retries_and_give_ups(tmp_cfg, monkeypatch, capsys):
    from pydiffwatch import __main__ as cli
    conn = store.connect(tmp_cfg); store.init_schema(conn)
    for i, stage in enumerate(("metadata_retry", "gave_up", "gave_up")):
        rid = store.record_release(conn, f"p{i}", "1.0", i, False, None, "sdist")
        store.update_stage(conn, rid, stage)
    monkeypatch.setattr(cli, "_cfg", lambda args: tmp_cfg)
    monkeypatch.setattr(cli.egress, "install_guard", lambda cfg: None)
    monkeypatch.setattr(sys, "argv", ["pydiffwatch", "pending"])
    cli.main()
    out = capsys.readouterr().out
    assert "1 release(s) being retried" in out and "2 given up on after 3 attempts" in out


def test_a_retried_release_that_then_fails_to_download_stays_in_the_retry_queue(tmp_cfg, monkeypatch):
    # Behind the cursor, a plain fetch_failed would never be looked at again: it must keep counting attempts.
    _feed(monkeypatch, [NewRelease("victim", "1.1", 10)])
    state = {"meta_fails": True}

    def pkg_json(pkg, cfg):
        if state["meta_fails"]:
            raise TimeoutError("metadata hung")
        return _VICTIM

    def download(url, cfg):
        raise urllib.error.URLError("connection reset")
    monkeypatch.setattr(fetcher, "_package_json", pkg_json)
    monkeypatch.setattr(fetcher, "_download", download)
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    state["meta_fails"] = False
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    conn = store.connect(tmp_cfg)
    row = conn.execute("SELECT stage, fetch_attempts FROM releases WHERE package='victim'").fetchone()
    assert (row["stage"], row["fetch_attempts"]) == ("metadata_retry", 2)


# Final review: every non-terminal per-release failure goes to the same bounded retry queue. A failed sdist
# download (incl. a fetch_deadline_s expiry) or a diff/triage exception used to be `fetch_failed`, which held
# the cursor at that release on every tick for as long as the failure lasted — forever, if it was deterministic.

def test_a_failed_sdist_download_is_retried_without_pinning_the_cursor(tmp_cfg, monkeypatch):
    _feed(monkeypatch, [NewRelease("victim", "1.1", 10), NewRelease("after", "1.0", 11)])
    monkeypatch.setattr(fetcher, "_package_json",
                        lambda pkg, cfg: _VICTIM if pkg == "victim" else _meta(pkg, [("1.0", "2026-01-01T00:00:00Z")]))
    tries = []

    def download(url, cfg):
        if "victim" in url:
            tries.append(url)
            raise TimeoutError("download took longer than 120s")
        return NEW
    monkeypatch.setattr(fetcher, "_download", download)
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    conn = store.connect(tmp_cfg)
    assert store.get_last_serial(conn) == 11
    row = conn.execute("SELECT stage, fetch_note FROM releases WHERE package='victim'").fetchone()
    assert row["stage"] == "metadata_retry"
    assert "TimeoutError" in row["fetch_note"] and "120s" in row["fetch_note"]
    for _ in range(3):
        orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    assert store.get_stage(conn, "victim", "1.1") == "gave_up"
    assert len([u for u in tries if u.endswith("/1.1")]) == 3               # bounded
    assert store.metadata_retry_counts(conn) == {"retrying": 0, "gave_up": 1}


def test_a_diff_or_triage_failure_is_retried_without_pinning_the_cursor(tmp_cfg, monkeypatch):
    from pydiffwatch import engine
    _feed(monkeypatch, [NewRelease("victim", "1.1", 10), NewRelease("after", "1.0", 11)])
    monkeypatch.setattr(fetcher, "_package_json",
                        lambda pkg, cfg: _VICTIM if pkg == "victim" else _meta(pkg, [("1.0", "2026-01-01T00:00:00Z")]))
    monkeypatch.setattr(fetcher, "_download", lambda url, cfg: NEW)
    real = engine.triage

    def triage(d, *a, **k):
        if d.package == "victim":
            raise RecursionError("maximum recursion depth exceeded")
        return real(d, *a, **k)
    monkeypatch.setattr(engine, "triage", triage)
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    conn = store.connect(tmp_cfg)
    assert store.get_last_serial(conn) == 11
    row = conn.execute("SELECT stage, fetch_note FROM releases WHERE package='victim'").fetchone()
    assert row["stage"] == "metadata_retry" and "RecursionError" in row["fetch_note"]


def test_a_retry_that_fails_after_the_download_notes_the_real_error(tmp_cfg, monkeypatch):
    # The retry queue's own fallback used to note the result's type name, which read "ArtifactSet".
    from pydiffwatch import engine
    _feed(monkeypatch, [NewRelease("victim", "1.1", 10)])
    state = {"meta_fails": True}

    def pkg_json(pkg, cfg):
        if state["meta_fails"]:
            raise TimeoutError("metadata hung")
        return _VICTIM
    monkeypatch.setattr(fetcher, "_package_json", pkg_json)
    monkeypatch.setattr(fetcher, "_download", lambda url, cfg: NEW)
    monkeypatch.setattr(engine, "triage", lambda *a, **k: (_ for _ in ()).throw(ValueError("bad rule state")))
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    state["meta_fails"] = False
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    conn = store.connect(tmp_cfg)
    row = conn.execute("SELECT stage, fetch_attempts, fetch_note FROM releases WHERE package='victim'").fetchone()
    assert (row["stage"], row["fetch_attempts"]) == ("metadata_retry", 2)
    assert "ValueError" in row["fetch_note"] and "bad rule state" in row["fetch_note"]
    assert "ArtifactSet" not in row["fetch_note"]


def test_pending_does_not_call_every_retry_a_metadata_failure(tmp_cfg, monkeypatch, capsys):
    from pydiffwatch import __main__ as cli
    conn = store.connect(tmp_cfg); store.init_schema(conn)
    rid = store.record_release(conn, "p", "1.0", 1, False, None, "sdist")
    store.update_stage(conn, rid, "metadata_retry")
    monkeypatch.setattr(cli, "_cfg", lambda args: tmp_cfg)
    monkeypatch.setattr(cli.egress, "install_guard", lambda cfg: None)
    monkeypatch.setattr(sys, "argv", ["pydiffwatch", "pending"])
    cli.main()
    out = capsys.readouterr().out
    assert "1 release(s) being retried" in out and "metadata failed" not in out


# --- Task 8: retry bookkeeping -----------------------------------------------------------------------------

def test_a_release_that_succeeds_clears_its_fetch_note_and_attempts(tmp_cfg, monkeypatch):
    # D2 / (d): a later success must not leave the old error (or its count) on the row.
    _feed(monkeypatch, [NewRelease("victim", "1.1", 10)])
    state = {"fail": True}

    def pkg_json(pkg, cfg):
        if state["fail"]:
            raise TimeoutError("metadata hung")
        return _VICTIM
    monkeypatch.setattr(fetcher, "_package_json", pkg_json)
    monkeypatch.setattr(fetcher, "_download", lambda url, cfg: NEW)
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    state["fail"] = False
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    conn = store.connect(tmp_cfg)
    row = conn.execute("SELECT stage, fetch_attempts, fetch_note FROM releases WHERE package='victim'").fetchone()
    assert (row["stage"], row["fetch_attempts"], row["fetch_note"]) == ("triaged", 0, None)


def test_entering_the_wheel_only_wait_resets_the_failure_count(tmp_cfg):
    # (d): 3 failed fetches, then a successful one that parks the release in no_sdist_wait. One failed re-check
    # after the grace is a first failure, not the 4th: it must retry, not give up with a download-failure alert.
    conn = store.connect(tmp_cfg); store.init_schema(conn)
    rel = NewRelease("sw", "1.1", 10)
    for i in range(store.METADATA_ATTEMPTS - 1):
        orchestrator._process_fetched(tmp_cfg, conn, None, None, rel, TimeoutError(f"hung {i}"))
    orchestrator._process_fetched(tmp_cfg, conn, None, None, rel, fetcher.NoSdist(switched_from="1.0"))
    row = conn.execute("SELECT stage, fetch_attempts, fetch_note FROM releases WHERE package='sw'").fetchone()
    assert (row["stage"], row["fetch_attempts"], row["fetch_note"]) == ("no_sdist_wait", 0, None)
    conn.execute("UPDATE releases SET recheck_at=0 WHERE package='sw'"); conn.commit()
    orchestrator._process_fetched(tmp_cfg, conn, None, None, rel, TimeoutError("recheck hung"))
    assert store.get_stage(conn, "sw", "1.1") == "metadata_retry"
    # Its grace is already spent: the retry that sees it still wheel-only decides it, instead of starting a new
    # wait (with the count reset, wait -> failed re-check -> wait would otherwise never end).
    orchestrator._process_fetched(tmp_cfg, conn, None, None, rel, fetcher.NoSdist(switched_from="1.0"))
    assert store.get_stage(conn, "sw", "1.1") == "no_sdist"


def test_each_retry_gets_a_longer_deadline_and_logs_its_attempt(tmp_cfg, monkeypatch, caplog, scan_stub):
    # (i), npm #26: attempt k is passed to the fetcher, which gives the package JSON and sdist downloads k times
    # their deadlines (test_fetch_deadlines checks which requests scale; attempt 1 is x1, so the first try is as
    # strict as ever), and the log line names the error and the attempt.
    import logging
    _feed(monkeypatch, [NewRelease("slow", "1.0", 10)])
    seen = []

    def fetch(cfg, rel, attempt=1):
        seen.append(attempt)
        raise TimeoutError("download took too long")
    scan_stub.fetch(fetch)
    with caplog.at_level(logging.WARNING, logger="pydiffwatch.orchestrator"):
        for _ in range(store.METADATA_ATTEMPTS):
            orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    assert seen == list(range(1, store.METADATA_ATTEMPTS + 1))
    msgs = [r.getMessage() for r in caplog.records if "slow==1.0" in r.getMessage()]
    assert "(TimeoutError: download took too long); will retry next tick (attempt 1 of 3)" in msgs[0]
    assert "attempt 2 of 3" in msgs[1] and "giving up after 3 attempts" in msgs[2]


def _backlog(conn):
    import datetime
    old = (datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=3, minutes=5)).isoformat()
    for i, stage in enumerate(("metadata_retry", "metadata_retry", "gave_up")):
        rid = store.record_release(conn, f"p{i}", "1.0", i, False, None, "sdist")
        store.update_stage(conn, rid, stage)
    conn.execute("UPDATE releases SET processed_at=? WHERE package='p0'", (old,)); conn.commit()


def test_pending_shows_the_age_of_the_oldest_retrying_release(tmp_cfg, monkeypatch, capsys):
    from pydiffwatch import __main__ as cli
    conn = store.connect(tmp_cfg); store.init_schema(conn)
    _backlog(conn)
    monkeypatch.setattr(cli, "_cfg", lambda args: tmp_cfg)
    monkeypatch.setattr(cli.egress, "install_guard", lambda cfg: None)
    monkeypatch.setattr(sys, "argv", ["pydiffwatch", "pending"])
    cli.main()
    out = capsys.readouterr().out
    assert "2 release(s) being retried (oldest first seen 3 hours ago)" in out and "1 given up on" in out


def test_the_dashboard_status_strip_shows_the_retry_backlog(tmp_cfg):
    conn = store.connect(tmp_cfg); store.init_schema(conn)
    _backlog(conn)
    html = orchestrator.export_dashboard(tmp_cfg).read_text()
    assert "2 scan(s) retrying (oldest first seen 3 hours ago) · 1 scan(s) given up" in html
    store.update_stage(conn, 1, "gave_up"); store.update_stage(conn, 2, "gave_up")
    html = orchestrator.export_dashboard(tmp_cfg).read_text()
    assert "retrying" not in html and "3 scan(s) given up" in html


def _victim_download(new_blob):
    def download(url, cfg):
        return new_blob if url.endswith("/1.1") else NEW
    return download


def _victim_json(monkeypatch):
    monkeypatch.setattr(fetcher, "_package_json",
                        lambda pkg, cfg: _VICTIM if pkg == "victim" else _meta(pkg, [("1.0", "2026-01-01T00:00:00Z")]))


def test_a_truncated_sdist_is_retried_then_given_up_with_the_error(tmp_cfg, monkeypatch, capsys):
    big = make_sdist({f"victim/f{i}.py": (f"x{i} = {i}\n" * 4000).encode() for i in range(20)})
    _feed(monkeypatch, [NewRelease("victim", "1.1", 10), NewRelease("after", "1.0", 11)])
    _victim_json(monkeypatch)
    monkeypatch.setattr(fetcher, "_download", _victim_download(big[: len(big) * 6 // 10]))
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    conn = store.connect(tmp_cfg)
    assert store.get_last_serial(conn) == 11                                  # never pins the cursor
    assert store.get_stage(conn, "victim", "1.1") == "metadata_retry"
    capsys.readouterr()
    for _ in range(3):
        orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    assert store.get_stage(conn, "victim", "1.1") == "gave_up"
    out = capsys.readouterr().out
    assert out.count("victim 1.1") == 1 and "3 times" in out and "EOFError:" in out


def test_a_bz2_sdist_is_retried_not_refused(tmp_cfg, monkeypatch, capsys):
    _feed(monkeypatch, [NewRelease("victim", "1.1", 10)])
    _victim_json(monkeypatch)
    monkeypatch.setattr(fetcher, "_download", _victim_download(b"BZh91AY&SY" + b"\x00" * 64))
    for _ in range(3):
        orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    conn = store.connect(tmp_cfg)
    assert store.get_stage(conn, "victim", "1.1") == "gave_up"
    assert "BadGzipFile" in capsys.readouterr().out


def test_a_zip_sdist_is_refused_once_without_retry(tmp_cfg, monkeypatch, capsys):
    _feed(monkeypatch, [NewRelease("victim", "1.1", 10)])
    _victim_json(monkeypatch)
    calls = []

    def download(url, cfg):
        calls.append(url)
        return b"PK\x03\x04" + b"\x00" * 64
    monkeypatch.setattr(fetcher, "_download", download)
    for _ in range(2):
        orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    conn = store.connect(tmp_cfg)
    assert store.get_stage(conn, "victim", "1.1") == "refused_to_extract"
    assert len([u for u in calls if u.endswith("/1.1")]) == 1
    out = capsys.readouterr().out
    assert out.count("victim 1.1") == 1
    assert "zip-sdist: it is a zip archive, which pydiffwatch does not unpack" in out


@pytest.mark.parametrize("prior", [b"PK\x03\x04" + b"\x00" * 64, NEW[: len(NEW) // 2]])
def test_a_zip_or_corrupt_prior_never_fails_the_new_release(tmp_cfg, monkeypatch, prior):
    _feed(monkeypatch, [NewRelease("victim", "1.1", 10)])
    _victim_json(monkeypatch)
    monkeypatch.setattr(fetcher, "_download", lambda url, cfg: NEW if url.endswith("/1.1") else prior)
    orchestrator.run_once(tmp_cfg, seed_if_fresh=False)
    conn = store.connect(tmp_cfg)
    row = conn.execute("SELECT stage, fetch_attempts, fetch_note FROM releases WHERE package='victim'").fetchone()
    assert row["stage"] not in ("metadata_retry", "gave_up", "refused_to_extract")
    assert row["fetch_attempts"] == 0 and "prior 1.0 sdist unavailable" in row["fetch_note"]
