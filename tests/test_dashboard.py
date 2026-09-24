from pydiffwatch import dashboard, store, orchestrator
from pydiffwatch.config import Config
from pydiffwatch.models import Verdict


# ---- pure-function tests (no DB) ----
def test_pypi_version_url():
    assert dashboard.pypi_version_url("requests", "2.31.0") == \
        "https://pypi.org/project/requests/2.31.0/"


def test_render_includes_version_url():
    out = dashboard.render_dashboard([{"package": "evilpkg", "version": "1.0.0",
                                       "classification": "malicious"}])
    assert "https://pypi.org/project/evilpkg/1.0.0/" in out


def test_render_flagged_has_report_link():
    out = dashboard.render_dashboard([{"package": "evilpkg", "version": "1.0.0",
                                       "classification": "malicious"}])
    assert "Report malware on PyPI" in out
    assert "https://pypi.org/project/evilpkg/" in out


def test_render_benign_has_no_report_link():
    out = dashboard.render_dashboard([{"package": "okpkg", "version": "2.0.0",
                                       "classification": "benign"}])
    assert "Report malware on PyPI" not in out
    assert "https://pypi.org/project/okpkg/2.0.0/" in out


def test_render_escapes_untrusted_package_name():
    out = dashboard.render_dashboard([{"package": "<script>alert(1)</script>",
                                       "version": "1.0.0", "classification": "malicious"}])
    assert "<script>alert(1)" not in out
    assert "&lt;script&gt;" in out


def test_render_partial_review_benign_gets_report_link_and_flagged_styling():
    # spec U2: a benign verdict routed to needs_adjudication (a file the model never saw carried
    # fired-rule weight) must not render as a clean, dimmed "benign" card — a person still needs to
    # look at it.
    out = dashboard.render_dashboard([{"package": "partpkg", "version": "1.0.0",
                                       "classification": "benign", "stage": "needs_adjudication"}])
    assert "Report malware on PyPI" in out
    assert 'class="card suspicious"' in out
    assert ">benign<" in out       # the model's actual classification is still shown as text


def test_render_counts_partial_review_benign_as_flagged_for_review():
    out = dashboard.render_dashboard([{"package": "partpkg", "version": "1.0.0",
                                       "classification": "benign", "stage": "needs_adjudication"}])
    assert "1 flagged for review" in out


def test_is_flagged():
    assert dashboard.is_flagged({"classification": "malicious"}) is True
    assert dashboard.is_flagged({"classification": "suspicious"}) is True
    assert dashboard.is_flagged({"classification": "benign"}) is False
    assert dashboard.is_flagged({"classification": "benign", "stage": "needs_adjudication"}) is True
    assert dashboard.is_flagged({"classification": "benign", "stage": "reviewed"}) is False


def test_is_flagged_honors_a_human_adjudication():
    # store.adjudicate never moves the release off its stage, so a human "benign" on a partial-review
    # release (still stage='needs_adjudication') must clear the flag -- and a human override the other
    # way (model said benign, human found it malicious) must keep it flagged.
    still_queued_but_cleared = {"classification": "benign", "stage": "needs_adjudication",
                                "human_label": "benign"}
    assert dashboard.is_flagged(still_queued_but_cleared) is False
    overridden_to_malicious = {"classification": "benign", "stage": "needs_adjudication",
                               "human_label": "malicious"}
    assert dashboard.is_flagged(overridden_to_malicious) is True


def test_render_after_human_adjudication_matches_the_human_label():
    # The badge must never contradict is_flagged's report-button/styling decision.
    cleared = dashboard.render_dashboard([{"package": "partpkg", "version": "1.0.0",
                                           "classification": "benign", "stage": "needs_adjudication",
                                           "human_label": "benign"}])
    assert "Report malware on PyPI" not in cleared
    assert 'class="card benign"' in cleared and ">benign<" in cleared

    overridden = dashboard.render_dashboard([{"package": "partpkg", "version": "1.0.0",
                                              "classification": "benign", "stage": "needs_adjudication",
                                              "human_label": "malicious"}])
    assert "Report malware on PyPI" in overridden
    assert 'class="card malicious"' in overridden and ">malicious<" in overridden


def test_render_orders_flagged_first():
    out = dashboard.render_dashboard([
        {"package": "benignpkg", "version": "1.0.0", "classification": "benign"},
        {"package": "malpkg", "version": "1.0.0", "classification": "malicious"},
    ])
    assert out.index("malpkg") < out.index("benignpkg")


# ---- DB-backed test ----
def _cfg(tmp_path):
    # reviewer_enabled=False -> export_dashboard's reviewer probe returns early without any socket
    # call, keeping these tests off the network and independent of process-wide socket state.
    return Config(db_path=tmp_path / "diffwatch.sqlite", reviewer_enabled=False)


def test_watch_refreshes_dashboard_each_tick_and_is_bounded(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    # don't hit PyPI: stub the scan so watch() only exercises its loop + dashboard refresh
    ticks = {"n": 0}
    monkeypatch.setattr(orchestrator, "run_once", lambda c, **k: ticks.__setitem__("n", ticks["n"] + 1))
    sleeps = []
    n = orchestrator.watch(cfg, interval=42, iterations=3, sleep_fn=sleeps.append)
    assert n == 3
    assert ticks["n"] == 3
    assert sleeps == [42, 42]  # sleeps between ticks, not after the last
    assert (cfg.db_path.parent / "dashboard.html").exists()


def test_watch_survives_a_failing_scan(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    def boom(c, **k):
        raise RuntimeError("scan exploded")
    monkeypatch.setattr(orchestrator, "run_once", boom)
    n = orchestrator.watch(cfg, iterations=2, sleep_fn=lambda _: None)
    assert n == 2  # daemon stayed up despite the scan failures
    assert (cfg.db_path.parent / "dashboard.html").exists()


def test_export_dashboard_writes_file(tmp_path):
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn)
    rid = store.record_release(conn, "evilpkg", "1.0.0", 1, False, "0.9.0", "diff")
    store.record_verdict(conn, rid, Verdict(
        package="evilpkg", version="1.0.0", classification="malicious",
        score=99.0, fired_rules=[], urgent=True,
        confidence=1.0, attack_type="install-hook-rce",
        reasoning="exfiltrates env", cited_hunk="setup.py:3", model="gemma-4-12b-it"))
    conn.close()
    out = orchestrator.export_dashboard(cfg)
    assert out.exists()
    assert "evilpkg" in out.read_text()


def test_render_shows_pending_llm_review_by_reason():
    status = dict(last_serial=None, last_poll_age=None, stale=False, releases_total=0, verdicts_total=0,
                  flagged_total=0, reviewer="x", model_reachable=None,
                  pending_review={"too_large": 2, "endpoint_unreachable": 5})
    html = dashboard.render_dashboard([], status=status)
    assert "7 pending LLM review" in html
    assert "too_large: 2" in html and "endpoint_unreachable: 5" in html


def test_render_shows_reviewer_guard_state():
    html = dashboard.render_dashboard([], status={"guard": {
        "state": "open", "detail": "breaker open after timeout", "tok_s": 85.0, "cap_chars": 52020,
        "host_memory": "swap 83% used"}})
    assert "reviews paused (timeout)" in html and "85 tok/s" in html and "52,020" in html
    assert "swap 83% used" in html
