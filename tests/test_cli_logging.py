"""The CLI shows pydiffwatch's own log lines (INFO and up) on stderr, with timestamps. Before this, nothing
configured logging, so in `run` and `watch` these INFO lines (the per-release scan timing, no_sdist_wait parking)
were dropped, and the WARNINGs appeared only through logging's last-resort handler, without a timestamp."""
import logging, re, sys

from pydiffwatch import __main__ as cli


def _run_cli(monkeypatch, tmp_cfg, run):
    monkeypatch.setattr(cli, "_cfg", lambda args: tmp_cfg)
    monkeypatch.setattr(cli.egress, "install_guard", lambda cfg: None)
    monkeypatch.setattr(cli, "run_once", run)
    monkeypatch.setattr(sys, "argv", ["pydiffwatch", "run"])
    cli.main()


def test_the_cli_prints_pydiffwatch_info_and_warnings_to_stderr(monkeypatch, capsys, tmp_cfg):
    def run(cfg, **k):
        log = logging.getLogger("pydiffwatch.orchestrator")
        log.info("scanned p==1.0 in 12 ms (extract, diff, triage)")
        log.warning("scan failed for p==1.1 (SandboxError: boom); will retry next tick (attempt 1 of 3)")
        logging.getLogger("some.library").info("third-party chatter")
        return 1
    _run_cli(monkeypatch, tmp_cfg, run)
    err = capsys.readouterr().err
    assert re.search(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d INFO scanned p==1\.0 in 12 ms \(extract, diff, triage\)$",
                     err, re.M)
    assert re.search(r"^\S+ \S+ WARNING scan failed for p==1\.1 \(SandboxError: boom\)", err, re.M)
    assert "third-party chatter" not in err


def test_each_line_is_printed_once_however_often_main_runs(monkeypatch, capsys, tmp_cfg):
    _run_cli(monkeypatch, tmp_cfg, lambda cfg, **k: 0)
    _run_cli(monkeypatch, tmp_cfg, lambda cfg, **k: logging.getLogger("pydiffwatch.sandbox").info("once") or 0)
    assert capsys.readouterr().err.count("INFO once") == 1
