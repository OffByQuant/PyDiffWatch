from pydiffwatch.config import Config
from pydiffwatch import store, notifier
from pydiffwatch.models import Verdict


def _conn(tmp_path):
    cfg = Config(db_path=tmp_path / "n.sqlite", webhook_url=None)
    c = store.connect(cfg); store.init_schema(c)
    rid = store.record_release(c, "pkg", "1.0", 1, False, "0.9", "sdist")
    return cfg, c, rid


def test_render_includes_llm_fields_when_present(tmp_path, capsys):
    cfg, c, rid = _conn(tmp_path)
    v = Verdict("pkg", "1.0", "malicious", 80.0, [], True, confidence=0.93,
                attack_type="credential-exfil", reasoning="reads ~/.aws and POSTs it",
                cited_hunk="pkg/__init__.py:4-9", recommended_action="report-to-pypi",
                model="claude-opus-4-8")
    assert notifier.emit(cfg, c, v, rid) is True
    out = capsys.readouterr().out
    assert "malicious" in out and "credential-exfil" in out
    assert "reads ~/.aws" in out and "pkg/__init__.py:4-9" in out


def test_render_heuristic_only_alert_still_works(tmp_path, capsys):
    cfg, c, rid = _conn(tmp_path)
    v = Verdict("pkg", "1.0", "suspicious-heuristic", 50.0, [], False)
    assert notifier.emit(cfg, c, v, rid) is True
    assert "suspicious-heuristic" in capsys.readouterr().out


def test_escalation_renotifies_but_same_classification_dedupes(tmp_path):
    cfg, c, rid = _conn(tmp_path)
    heur = Verdict("pkg", "1.0", "suspicious-heuristic", 50.0, [], False)
    llm = Verdict("pkg", "1.0", "malicious", 80.0, [], True, confidence=0.9,
                  attack_type="dropper", reasoning="x", cited_hunk="a:1-2",
                  recommended_action="report-to-pypi", model="claude-sonnet-4-6")
    assert notifier.emit(cfg, c, heur, rid) is True            # first alert
    assert notifier.emit(cfg, c, llm, rid) is True             # escalation -> re-notify (diff classification)
    assert notifier.emit(cfg, c, llm, rid) is False            # exact repeat -> deduped
