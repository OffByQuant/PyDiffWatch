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


def test_render_partial_review_shows_badge_model_classification_and_no_report_link():
    # spec U2: a benign verdict routed to needs_adjudication with reasoning "reviewed partially: ..."
    # (a file the model never saw carried fired-rule weight) is a tool gap, not a model finding — it
    # must not carry a "Report malware" button, but a person still needs to look at it.
    out = dashboard.render_dashboard([{"package": "partpkg", "version": "1.0.0",
                                       "classification": "benign", "stage": "needs_adjudication",
                                       "model": "gemma", "reasoning": "reviewed partially: setup.py not shown"}])
    assert "Report malware on PyPI" not in out
    assert 'class="badge partial">partial review<' in out
    assert "model: benign" in out


def test_render_partial_review_with_model_malicious_keeps_report_link():
    out = dashboard.render_dashboard([{"package": "partpkg", "version": "1.0.0",
                                       "classification": "malicious", "stage": "needs_adjudication",
                                       "model": "gemma", "reasoning": "reviewed partially: setup.py not shown"}])
    assert "Report malware on PyPI" in out


def test_render_not_scanned_shows_badge_reason_and_no_report_link():
    # spec: model='none' (UNREVIEWED) rows are a tool gap, not a model finding. The historical
    # placeholder classification is 'suspicious', but that must never surface as styling or a badge.
    out = dashboard.render_dashboard([{"package": "gappkg", "version": "1.0.0",
                                       "classification": "suspicious", "model": "none",
                                       "reasoning": "UNREVIEWED: pydiffwatch refused to fetch it."}])
    assert "Report malware on PyPI" not in out
    assert 'class="badge not_scanned">not scanned<' in out
    assert 'class="card not_scanned"' in out
    assert 'class="card malicious"' not in out and 'class="card suspicious"' not in out
    assert 'class="badge malicious"' not in out and 'class="badge suspicious"' not in out
    assert "UNREVIEWED: pydiffwatch refused to fetch it." in out
    assert "https://pypi.org/project/gappkg/" in out


def test_render_not_scanned_with_human_malicious_label_keeps_report_link():
    out = dashboard.render_dashboard([{"package": "gappkg", "version": "1.0.0",
                                       "classification": "suspicious", "model": "none",
                                       "reasoning": "UNREVIEWED: refused.", "human_label": "malicious"}])
    assert "Report malware on PyPI" in out
    assert 'class="card malicious"' in out


def test_render_model_malicious_keeps_report_link():
    out = dashboard.render_dashboard([{"package": "evilpkg", "version": "1.0.0",
                                       "classification": "malicious", "model": "gemma"}])
    assert "Report malware on PyPI" in out


def test_is_flagged():
    assert dashboard.is_flagged({"classification": "malicious"}) is True
    assert dashboard.is_flagged({"classification": "suspicious"}) is True
    assert dashboard.is_flagged({"classification": "benign"}) is False
    # a not-scanned row's placeholder classification ('suspicious') must not count as flagged
    assert dashboard.is_flagged({"classification": "suspicious", "model": "none"}) is False
    assert dashboard.is_flagged({"classification": "suspicious", "model": "none",
                                 "human_label": "malicious"}) is True


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
    status = dict(last_serial=None, last_poll_age=None, stale=False, releases_total=0,
                  model_reviewed_total=0, model_flagged_total=0, partial_total=0, not_scanned_total=0,
                  reviewer="x", model_reachable=None,
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


def test_rank_uses_the_human_label_like_the_badge_and_the_flagged_count(tmp_path):
    # (h), npm #24: a model-malicious release a person cleared as benign sinks below the flagged ones, and a
    # model-benign one a person labelled malicious rises to the top. The status strip's count agrees.
    rows = [{"package": "cleared", "version": "1", "classification": "malicious", "human_label": "benign"},
            {"package": "queued", "version": "1", "classification": "suspicious"},
            {"package": "caught", "version": "1", "classification": "benign", "human_label": "malicious"}]
    out = dashboard.render_dashboard(rows)
    assert out.index("caught") < out.index("queued") < out.index("cleared")
    assert "2 flagged by the model" in out


def test_rank_orders_not_scanned_and_partial_between_suspicious_and_benign():
    rows = [{"package": "benignpkg", "version": "1", "classification": "benign"},
            {"package": "gappkg", "version": "1", "classification": "suspicious", "model": "none"},
            {"package": "partpkg", "version": "1", "classification": "benign",
             "reasoning": "reviewed partially: x", "model": "m"},
            {"package": "suspkg", "version": "1", "classification": "suspicious", "model": "m"},
            {"package": "malpkg", "version": "1", "classification": "malicious", "model": "m"}]
    out = dashboard.render_dashboard(rows)
    order = sorted(("malpkg", "suspkg", "gappkg", "partpkg", "benignpkg"), key=out.index)
    assert order[0] == "malpkg" and order[1] == "suspkg" and order[-1] == "benignpkg"
    assert set(order[2:4]) == {"gappkg", "partpkg"}


def test_render_counts_split_model_reviewed_flagged_partial_and_not_scanned():
    rows = [{"package": "a", "version": "1", "classification": "malicious", "model": "m"},
            {"package": "b", "version": "1", "classification": "benign", "model": "m"},
            {"package": "c", "version": "1", "classification": "benign", "model": "m",
             "reasoning": "reviewed partially: x"},
            {"package": "d", "version": "1", "classification": "suspicious", "model": "none"},
            {"package": "e", "version": "1", "classification": "suspicious", "model": "none"}]
    out = dashboard.render_dashboard(rows)
    assert "3 model-reviewed" in out
    assert "1 flagged by the model" in out
    assert "1 partial review" in out
    assert "2 not scanned" in out
    assert "need manual review" in out


def test_export_dashboard_status_counts_split_model_reviewed_and_not_scanned(tmp_path):
    cfg = Config(db_path=tmp_path / "diffwatch.sqlite", reviewer_enabled=False)
    conn = store.connect(cfg); store.init_schema(conn)
    rid1 = store.record_release(conn, "evilpkg", "1.0.0", 1, False, "0.9.0", "diff")
    store.record_verdict(conn, rid1, Verdict("evilpkg", "1.0.0", "malicious", 99.0, [], True, model="m"))
    rid2 = store.record_release(conn, "gappkg", "1.0.0", 2, False, "0.9.0", "diff")
    store.record_verdict(conn, rid2, Verdict("gappkg", "1.0.0", "suspicious", 0.0, [], False,
                                             reasoning="UNREVIEWED: refused.", model="none"))
    conn.close()
    out = orchestrator.export_dashboard(cfg).read_text()
    assert "1 model-reviewed" in out
    assert "1 flagged by the model" in out
    assert "1 not scanned" in out


def test_a_labelled_card_shows_your_verdict_your_note_and_what_the_model_said(tmp_path):
    # npm #24: "your verdict: X — <note> · model said Y", the note escaped like every other untrusted string.
    cfg = Config(db_path=tmp_path / "db.sqlite", lock_path=tmp_path / "l", reviewer_enabled=False)
    conn = store.connect(cfg); store.init_schema(conn)
    rid = store.record_release(conn, "caught", "1.0", 1, False, None, "sdist")
    store.record_verdict(conn, rid, Verdict("caught", "1.0", "benign", 60.0, [], False, model="m"))
    store.adjudicate(conn, rid, "malicious", "curl|sh in setup.py <script>")
    out = orchestrator.export_dashboard(cfg).read_text()
    assert "your verdict: malicious — curl|sh in setup.py &lt;script&gt; · model said benign" in out
    assert "<script>" not in out


def test_a_card_without_a_note_or_a_disagreement_keeps_the_line_short():
    out = dashboard.render_dashboard([{"package": "p", "version": "1", "classification": "malicious",
                                       "human_label": "malicious"}])
    assert "your verdict: malicious</div>" in out
    assert "your verdict" not in dashboard.render_dashboard([{"package": "p", "version": "1",
                                                              "classification": "malicious"}])


def test_the_retry_backlog_leaves_the_last_poll_age_alone():
    out = dashboard.render_dashboard([], status={"last_poll_age": "2 minutes ago", "retry": {
        "retrying": 1, "gave_up": 0, "oldest_retrying_age": "3 hours ago"}})
    assert "last poll: 2 minutes ago" in out and "1 scan(s) retrying (oldest first seen 3 hours ago)" in out
