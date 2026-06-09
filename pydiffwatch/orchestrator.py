import dataclasses, datetime, fcntl, json, logging, os
from concurrent.futures import ThreadPoolExecutor
from . import ingest, fetcher, differ, engine, rules, notifier, store, reviewer, egress, dashboard
from .config import Config
from .models import Verdict, NewRelease, FiredRule

logger = logging.getLogger(__name__)

_FLAGGED = ("malicious", "suspicious")

# Stages that represent a completed analysis or permanent decision; skipped on future ticks.
# review_failed is NON-terminal (LLM down -> retry next tick for a real verdict).
TERMINAL = {"triaged", "alerted", "reviewed", "new_package_skipped", "needs_adjudication",
            "refused_to_extract", "no_sdist", "refused_to_fetch"}


def _load_ruleset(cfg):
    return rules.load_rules(cfg.rules_dir)


def _build_reviewer(cfg):
    """Construct the reviewer for this run, or None to use the heuristic-only path. The default
    OpenAI-compatible backend needs no key; the anthropic backend requires ANTHROPIC_API_KEY."""
    if not cfg.reviewer_enabled:
        logger.info("reviewer disabled; heuristic-only this run")
        return None
    if cfg.reviewer.provider == "anthropic" and not os.environ.get("ANTHROPIC_API_KEY"):
        logger.info("anthropic reviewer backend selected but no ANTHROPIC_API_KEY; heuristic-only this run")
        return None
    return reviewer.Reviewer(cfg)


def _review_escalated(cfg, conn, rvw, d, tr, rid):
    """Triage flagged this release. Get an LLM verdict; on LLM failure fall back to a heuristic
    alert (signal not dropped) and leave the release retryable."""
    if rvw is None:                                   # reviewer disabled / no API key -> heuristic
        notifier.emit(cfg, conn, Verdict(d.package, d.version, "suspicious-heuristic",
                                         tr.score, tr.fired_rules, False), rid)
        store.update_stage(conn, rid, "alerted", tr.score, None)
        return
    try:
        verdict = rvw.review(d, tr)
    except reviewer.ReviewUnavailable:
        logger.warning("LLM unavailable for %s==%s; heuristic fallback, will retry", d.package, d.version)
        notifier.emit(cfg, conn, Verdict(d.package, d.version, "suspicious-heuristic",
                                         tr.score, tr.fired_rules, False), rid)
        store.update_stage(conn, rid, "review_failed", tr.score, None)   # non-terminal -> retry next tick
        return
    store.record_verdict(conn, rid, verdict)
    # Route by the model's classification. A `suspicious` verdict is queued for human adjudication — it
    # is NOT alerted. benign is saved silently; malicious (or any unexpected class) alerts immediately.
    if verdict.classification == "benign":
        store.update_stage(conn, rid, "reviewed", tr.score, None)            # saved silently, no alert
    elif verdict.classification == "suspicious":
        store.update_stage(conn, rid, "needs_adjudication", tr.score, None)  # -> `pydiffwatch pending`
    else:                                                                   # malicious / unexpected
        notifier.emit(cfg, conn, verdict, rid)
        store.update_stage(conn, rid, "reviewed", tr.score, None)


def _fetch_one(cfg, rel):
    """Worker half of the pipeline — runs OFF the main thread. Does NO sqlite and NO notifier work
    (sqlite is single-threaded), only network + in-memory extraction (incl. PyPI-baseline resolution).
    Returns the ArtifactSet, None (no sdist), or the Exception it caught, for the main thread to map."""
    try:
        return fetcher.fetch_artifacts(cfg, rel)
    except Exception as e:        # incl. RefusedToFetch/RefusedToExtract — mapped on the main thread
        return e


def _process_fetched(cfg, conn, rvw, ruleset, rel, result) -> bool:
    """Main-thread half: record the release, map a completed fetch `result` (ArtifactSet | None |
    Exception) to a stage, diff/triage/review, emit alerts. ALL sqlite + notifier work happens here.
    Returns True iff the release reached a terminal stage."""
    rid = store.record_release(conn, rel.package, rel.version, rel.serial, False, None, "sdist")
    if isinstance(result, fetcher.RefusedToFetch):
        store.update_stage(conn, rid, "refused_to_fetch")
        return True   # deterministic refusal (over-size) — terminal
    if isinstance(result, fetcher.RefusedToExtract):
        store.update_stage(conn, rid, "refused_to_extract")
        notifier.emit(cfg, conn, Verdict(rel.package, rel.version,
                      "suspicious-heuristic", 0.0, [], False), rid)
        return True   # terminal: permanent suspicious decision recorded
    if isinstance(result, Exception):
        logger.warning("fetch_failed for %s==%s; will retry next tick", rel.package, rel.version)
        store.update_stage(conn, rid, "fetch_failed")
        return False  # non-terminal: cursor must not advance past this release
    if result is None:
        store.update_stage(conn, rid, "no_sdist")   # no sdist for this version — permanent
        return True
    store.set_baseline(conn, rid, result.prior_version, result.is_new_package)
    if result.maintainer_metadata is not None:
        store.update_release_metadata(conn, rid, json.dumps(result.maintainer_metadata))
    if result.is_new_package and cfg.new_package_policy == "skip":
        store.update_stage(conn, rid, "new_package_skipped")
        return True   # terminal: new packages are ignored under the skip policy
    try:
        d = differ.build_diff(result)
        store.update_stage(conn, rid, "diffed")
        prior_meta = (store.get_release_metadata(conn, rel.package, result.prior_version)
                      if result.prior_version else None)
        tr = engine.triage(d, cfg, ruleset, {"current": result.maintainer_metadata, "prior": prior_meta})
        store.update_stage(conn, rid, "triaged", tr.score,
                           json.dumps([r.__dict__ for r in tr.fired_rules]))
        # Persist the flagged payload code itself (not just file:line metadata) so the DB is a
        # self-contained takedown-report source that survives the package being pulled from PyPI.
        ev = reviewer.build_evidence(d, tr, max_chars=cfg.evidence_max_chars)
        if ev:
            store.update_evidence(conn, rid, ev)
        if tr.escalate:
            _review_escalated(cfg, conn, rvw, d, tr, rid)
        return True   # terminal for THIS tick (review_failed retried next tick)
    except Exception:
        logger.exception("processing failed for %s==%s; will retry next tick", rel.package, rel.version)
        store.update_stage(conn, rid, "fetch_failed")
        return False  # non-terminal: cursor must not advance past this release


def seed_now(cfg: Config):
    """Set the cursor to PyPI's current serial so monitoring starts from now (no historical crawl).
    Returns the seeded serial, or None if PyPI's current serial could not be read."""
    conn = store.connect(cfg); store.init_schema(conn)
    s = ingest.current_serial(cfg)
    if s is not None:
        store.set_last_serial(conn, s)
    return s


def run_once(cfg: Config, *, seed_if_fresh: bool = True) -> int:
    if not egress.is_installed():
        # The CLI installs the in-process egress guard at entry; a library caller importing run_once
        # directly does not. Surface it (don't auto-install: a library mutating global socket state is
        # worse than the gap). Call egress.install_guard(cfg), or rely on the OS-level boundary.
        logger.warning("egress guard not installed; this process has no in-process host allowlist "
                       "(see docs/hardening/egress-allowlist.md or call egress.install_guard(cfg))")
    cfg.lock_path.parent.mkdir(parents=True, exist_ok=True)
    # "a+" (not "w"): opening must NOT truncate, so a run that loses the lock can still read the holder
    # info the winner wrote below and report who's running.
    lock = open(cfg.lock_path, "a+")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lock.seek(0)
        holder = lock.read().strip()
        lock.close()
        who = f" ({holder})" if holder else ""
        print(
            f"[pydiffwatch] a scan is already running{who}; this invocation is exiting so the two "
            f"don't collide.\n"
            f"  lock file: {cfg.lock_path}\n"
            f"  - If that's your scheduled run (cron/systemd/CI), this is expected: space the schedule "
            f"so one tick finishes before the next starts.\n"
            f"  - If you're sure nothing is running, a previous run was likely killed or hung mid-fetch "
            f"and still holds the lock. Kill the reported pid and re-run. The lock is an OS-level "
            f"advisory lock that frees automatically when the holding process exits, so deleting the "
            f"lock file does NOT release a live lock — leave it in place.")
        return 0
    # Lock held. Record who holds it so a colliding run can report it above; flock frees on close/exit.
    lock.seek(0); lock.truncate()
    lock.write(f"pid={os.getpid()} since={datetime.datetime.now(datetime.UTC).isoformat()}"); lock.flush()
    try:
        conn = store.connect(cfg); store.init_schema(conn)
        last = store.get_last_serial(conn)
        # A fresh cursor starts monitoring from NOW, not PyPI genesis. Seed it to the current serial
        # and process nothing this tick; the next tick polls forward. --backfill opts out.
        if seed_if_fresh and last == 0:
            now_serial = ingest.current_serial(cfg)
            if now_serial is None:
                logger.warning("fresh cursor but PyPI current serial unavailable; skipping run "
                               "(retry next tick). Use 'run --backfill' to process from genesis.")
                return 0
            store.set_last_serial(conn, now_serial)
            logger.info("fresh cursor seeded to PyPI serial %d; monitoring starts now", now_serial)
            return 0
        rvw = _build_reviewer(cfg)
        ruleset = _load_ruleset(cfg)
        releases = ingest.changes_since(cfg, last)[:cfg.max_releases_per_run]
        prepared = [(rel, store.get_stage(conn, rel.package, rel.version)) for rel in releases]

        # Fetch concurrently in a bounded window but CONSUME results in ascending-serial order on the
        # main thread so the cursor-advance invariant holds: advance only to the highest serial such
        # that EVERY release at or before it reached a terminal stage.
        advance_to = store.get_last_serial(conn)
        blocked = False
        W = max(1, cfg.fetch_concurrency)
        with ThreadPoolExecutor(max_workers=W) as ex:
            for start in range(0, len(prepared), W):
                window = prepared[start:start + W]
                futs = {i: ex.submit(_fetch_one, cfg, rel)
                        for i, (rel, stg) in enumerate(window) if stg not in TERMINAL}
                for i, (rel, stg) in enumerate(window):
                    if stg in TERMINAL:
                        terminal = True                      # already-terminal: nothing to fetch
                    else:
                        terminal = _process_fetched(cfg, conn, rvw, ruleset, rel, futs[i].result())
                    if terminal and not blocked:
                        advance_to = rel.serial
                    else:
                        blocked = True  # stop advancing past the first non-terminal release
        store.set_last_serial(conn, advance_to)
        return len(releases)
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN); lock.close()


def _rules_from_json(s):
    return [FiredRule(r["rule"], r["weight"], r["file"], tuple(r["lines"])) for r in json.loads(s or "[]")]


def list_pending(cfg: Config):
    """Suspicious LLM verdicts awaiting adjudication. Each item carries the model's verdict plus the
    stored payload evidence (or the diff re-fetched from PyPI when evidence is absent on older rows)."""
    conn = store.connect(cfg); store.init_schema(conn)
    ruleset = _load_ruleset(cfg)
    items = []
    for row in store.pending_adjudication(conn):
        stored = row["evidence"]
        diff_text, err = stored, None
        if not stored:                                    # older row with no captured payload -> re-fetch
            try:
                art = fetcher.fetch_artifacts(cfg, NewRelease(row["package"], row["version"], row["serial"]))
                if art is not None:
                    d = differ.build_diff(art)
                    tr = engine.triage(d, cfg, ruleset)
                    diff_text = reviewer.build_review_input(d, tr, max_chars=cfg.reviewer.max_input_chars)
            except Exception as e:
                err = f"{type(e).__name__}: {e}"
        items.append({"release_id": row["release_id"], "package": row["package"], "version": row["version"],
                      "classification": row["classification"], "confidence": row["confidence"],
                      "attack_type": row["attack_type"], "reasoning": row["reasoning"],
                      "cited_hunk": row["cited_hunk"], "diff_text": diff_text, "fetch_error": err,
                      "evidence_stored": stored is not None})
    conn.close()
    return items


def get_evidence(cfg: Config, release_id: int):
    """The stored flagged payload code for a release (TEXT), or None if absent/unknown."""
    conn = store.connect(cfg); store.init_schema(conn)
    try:
        return store.get_evidence(conn, release_id)
    finally:
        conn.close()


def backfill_evidence(cfg: Config, release_id: int | None = None, all_flagged: bool = False):
    """One-shot capture of flagged payload code for releases detected before evidence was persisted.
    Re-fetches the immutable sdist, reproduces the diff, and stores the rendered payload. A pulled
    package can no longer be re-fetched, so the capture is reported as failed rather than crashing.
    Default scope = the reportable set; all_flagged widens to every row with a fired rule."""
    conn = store.connect(cfg); store.init_schema(conn)
    ruleset = _load_ruleset(cfg)
    results = []
    try:
        for row in store.releases_needing_evidence(conn, release_id, all_flagged):
            pkg, ver = row["package"], row["version"]
            try:
                art = fetcher.fetch_artifacts(cfg, NewRelease(pkg, ver, row["serial"]))
                if art is None:
                    results.append({"package": pkg, "version": ver, "captured": False, "error": "no sdist"})
                    continue
                # A row detected as a first release was whole-package scanned (no baseline then). If a
                # predecessor exists today, reproduce the detection-time scan: treat every file as added.
                if row["is_first_release"]:
                    art = dataclasses.replace(art, prior_files={}, prior_version=None, is_new_package=True)
                d = differ.build_diff(art)
                tr = engine.triage(d, cfg, ruleset)
                ev = reviewer.build_evidence(d, tr, max_chars=cfg.evidence_max_chars)
                if not ev:
                    results.append({"package": pkg, "version": ver, "captured": False,
                                    "error": "no code payload to render"})
                    continue
                store.update_evidence(conn, row["release_id"], ev)
                results.append({"package": pkg, "version": ver, "captured": True, "error": None})
            except Exception as e:
                results.append({"package": pkg, "version": ver, "captured": False, "error": f"{type(e).__name__}: {e}"})
    finally:
        conn.close()
    return results


def watch(cfg: Config, interval: int = 300, out_path=None, iterations=None, sleep_fn=None):
    """Daemon loop: scan one tick, refresh the dashboard, sleep, repeat until Ctrl-C.
    A failed scan is logged and skipped (the daemon stays up); the dashboard is
    refreshed every tick so 'last poll' / reachability stay current. `iterations`
    and `sleep_fn` exist for tests; in production both default to forever / time.sleep."""
    import time
    sleep_fn = sleep_fn or time.sleep
    n = 0
    try:
        while iterations is None or n < iterations:
            try:
                run_once(cfg)
            except Exception:
                logger.exception("watch: scan tick failed; daemon continuing")
            export_dashboard(cfg, out_path=out_path)
            n += 1
            if iterations is not None and n >= iterations:
                break
            sleep_fn(interval)
    except KeyboardInterrupt:
        pass
    return n


def _probe_reviewer(cfg: Config):
    """(reachable, label): a localhost TCP probe of the LLM endpoint. The egress
    guard allowlists this host, so the connect is permitted. Returns (None, label)
    when there is nothing local to probe (reviewer disabled or a remote provider)."""
    import socket
    from urllib.parse import urlsplit
    rc = getattr(cfg, "reviewer", None)
    if not getattr(cfg, "reviewer_enabled", True) or rc is None:
        return None, "reviewer disabled"
    if rc.provider != "openai":
        return None, f"{rc.provider} (remote)"
    parts = urlsplit(rc.base_url)
    host, port = parts.hostname, parts.port or (443 if parts.scheme == "https" else 80)
    label = f"{host}:{port}"
    try:
        with socket.create_connection((host, port), timeout=1.5):
            return True, label
    except OSError:
        return False, label


def _poll_age(updated_at):
    if not updated_at:
        return None, False
    try:
        t = datetime.datetime.fromisoformat(updated_at)
        secs = (datetime.datetime.now(datetime.UTC) - t).total_seconds()
    except (ValueError, TypeError):
        return None, False
    return dashboard.humanize_age(secs), secs > 900  # stale after 15 min idle


def export_dashboard(cfg: Config, out_path=None, generated_at: str = ""):
    from pathlib import Path
    out = Path(out_path) if out_path else cfg.db_path.parent / "dashboard.html"
    conn = store.connect(cfg); store.init_schema(conn)
    try:
        rows = [dict(r) for r in store.all_verdicts(conn)]
        cur = store.get_cursor(conn)
        releases_total = store.count_releases(conn)
    finally:
        conn.close()
    reachable, reviewer_label = _probe_reviewer(cfg)
    age, stale = _poll_age(cur["updated_at"] if cur else None)
    status = {
        "last_serial": cur["last_serial"] if cur else None,
        "last_poll_age": age, "stale": stale,
        "releases_total": releases_total, "verdicts_total": len(rows),
        "flagged_total": sum(1 for r in rows if (r.get("classification") or "").lower() in _FLAGGED),
        "reviewer": reviewer_label, "model_reachable": reachable,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(dashboard.render_dashboard(rows, status=status, generated_at=generated_at))
    return out


def adjudicate(cfg: Config, release_id: int, label: str, note: str = ""):
    """Record the human verdict on a queued suspicious release. Sets human_label/note/adjudicated_at
    and emits an alert (model='human-adjudicator') unless cleared as benign. Returns a summary dict,
    or None if the release_id is not found."""
    conn = store.connect(cfg); store.init_schema(conn)
    try:
        rel = store.adjudicate(conn, release_id, label, note)
        if rel is None:
            return None
        alerted = False
        if label != "benign":
            v = Verdict(rel["package"], rel["version"], label, rel["triage_score"] or 0.0,
                        _rules_from_json(rel["triage_rules"]), label == "malicious",
                        reasoning=note or None, model="human-adjudicator")
            alerted = notifier.emit(cfg, conn, v, release_id)
        return {"package": rel["package"], "version": rel["version"], "label": label, "alerted": alerted}
    finally:
        conn.close()
