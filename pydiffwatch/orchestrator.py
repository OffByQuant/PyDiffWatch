import dataclasses, datetime, fcntl, json, logging, os, sqlite3, time
from concurrent.futures import ThreadPoolExecutor
from . import ingest, fetcher, differ, engine, rules, notifier, store, reviewer, egress, dashboard
from . import guard as guard_mod
from .config import Config
from .models import Verdict, NewRelease, FiredRule

logger = logging.getLogger(__name__)

_FLAGGED = ("malicious", "suspicious")

# Stages that represent a completed analysis or permanent decision; skipped on future ticks.
# pending_review is terminal for the cursor: the LLM-review queue retries it, not the scan. Likewise
# metadata_retry: failed metadata downloads are retried from the release rows, not the changelog.
TERMINAL = {"triaged", "alerted", "reviewed", "new_package_skipped", "needs_adjudication",
            "refused_to_extract", "no_sdist", "refused_to_fetch", "pending_review",
            "metadata_gone", "metadata_retry", "gave_up"}


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


def _endpoint_down(e) -> bool:
    cause = e.__cause__
    return isinstance(getattr(cause, "reason", cause), ConnectionRefusedError)


def _is_timeout(e) -> bool:
    cause = e.__cause__
    reason = getattr(cause, "reason", cause)
    return isinstance(reason, TimeoutError) or type(cause).__name__ == "APITimeoutError"


def review_lock_path(cfg):
    return cfg.lock_path.with_name(cfg.lock_path.name + ".review")


def _review_slot(cfg):
    """Blocking lock held while a review is at the model, so `review-pending` and the watch loop (separate
    processes) never have requests at one endpoint at the same time. Freed when the file is closed."""
    path = review_lock_path(cfg)
    path.parent.mkdir(parents=True, exist_ok=True)
    f = open(path, "a+")
    fcntl.flock(f, fcntl.LOCK_EX)
    return f



def _record(cfg, conn, rid, verdict, score):
    store.clear_pending(conn, rid)
    store.record_verdict(conn, rid, verdict)
    # Route by the model's classification. A `suspicious` verdict is queued for human adjudication — it
    # is NOT alerted. benign is saved silently; malicious (or any unexpected class) alerts immediately.
    if verdict.classification == "benign":
        store.clear_evidence(conn, rid)                                   # kept only where a person may act
        store.update_stage(conn, rid, "reviewed", score, None)            # saved silently, no alert
    elif verdict.classification == "suspicious":
        store.update_stage(conn, rid, "needs_adjudication", score, None)  # -> `pydiffwatch pending`
    else:                                                                 # malicious / unexpected
        notifier.emit(cfg, conn, verdict, rid)
        store.update_stage(conn, rid, "reviewed", score, None)


def _attempt_review(cfg, conn, rvw, rid, package, version, score, fired_rules, text, guard=None) -> bool:
    """One review attempt; on failure the release is (re)parked with the reason. Returns False when no more
    reviews should be sent now (endpoint unreachable, guard deferring, or the guard's breaker just opened),
    so a drain stops instead of hammering the server."""
    if guard is not None:
        why = guard.admit()
        if why:
            store.park_for_review(conn, rid, "model_busy", why, text)
            return False
    attempt = store.review_attempts(conn, rid) + 1
    t0 = time.monotonic()
    try:
        with _review_slot(cfg):
            verdict = rvw.review_text(package, version, score, fired_rules, text, attempt=attempt)
    except reviewer.ReviewUnavailable as e:
        logger.warning("LLM review failed for %s==%s (attempt %d): %s", package, version, attempt, e)
        if _endpoint_down(e):     # an outage, not this release's fault: don't spend an attempt
            store.park_for_review(conn, rid, "endpoint_unreachable", str(e), text)
            return False
        n = store.bump_review_attempts(conn, rid)
        store.park_for_review(conn, rid, "review_failed", f"{n} failed attempt(s): {e}", text)
        if guard is not None and _is_timeout(e):
            guard.record_timeout()
            return False
        return True
    if guard is not None and verdict.model == rvw.backend.primary_model:
        # Only a single primary-model call is a speed sample: an escalation spans two models (and a swap).
        # prompt_tokens cover the system prompt as well as the package content, so the chars must too.
        guard.record_success(getattr(rvw.backend, "last_usage", None), time.monotonic() - t0,
                             len(reviewer.SYSTEM_PROMPT) + len(text))
    _record(cfg, conn, rid, verdict, score)
    return True


def _review_escalated(cfg, conn, rvw, d, tr, rid, *, offline=False, guard=None):
    if rvw is None:
        notifier.emit(cfg, conn, Verdict(d.package, d.version, "suspicious-heuristic",
                                         tr.score, tr.fired_rules, False), rid)
        store.update_stage(conn, rid, "alerted", tr.score, None)
        return
    try:
        text = rvw.prepare(d, tr, cap=guard.input_cap_chars() if guard is not None else None)
    except reviewer.InputTooLarge as e:
        detail = f"{e}; {guard.cap_explain()}" if guard is not None else str(e)
        store.park_for_review(conn, rid, "too_large", detail, e.text)
    else:
        if offline:
            store.park_for_review(conn, rid, "endpoint_unreachable", "reviewer endpoint unreachable", text)
        else:
            _attempt_review(cfg, conn, rvw, rid, d.package, d.version, tr.score, tr.fired_rules, text, guard)
    if store.get_stage(conn, d.package, d.version) == "pending_review":
        # Not reviewed yet: alert on the heuristic now rather than wait for the queue to drain.
        notifier.emit(cfg, conn, Verdict(d.package, d.version, "suspicious-heuristic",
                                         tr.score, tr.fired_rules, False), rid)


def drain_pending(cfg, conn, rvw, *, auto: bool, reasons=None, limit=None, guard=None) -> int:
    """Review parked releases. auto (each tick): model_busy first, then unreachable-endpoint parks, failed
    reviews with attempts left, and too_large rows that now fit. Manual (`review-pending`): by default oversized
    releases and exhausted retries — run it with a larger-context model config. Inputs over this endpoint's cap are skipped
    (auto: re-parked as too_large). `limit` caps attempts, not successes. Returns the number reviewed."""
    if auto:
        reasons = ("model_busy", "endpoint_unreachable", "review_failed")
    elif not reasons:
        reasons = ("too_large", "review_failed")
    cap = guard.input_cap_chars() if guard is not None else cfg.reviewer.max_input_chars
    rows = store.pending_reviews(conn, reasons)
    if auto:      # oversized for an earlier cap (cold start, a smaller max_input_chars) but fits this one
        rows += store.pending_reviews(conn, ("too_large",), max_chars=cap)
    rows = sorted(rows,
                  key=lambda r: (r["pending_reason"] != "model_busy", r["release_id"]))
    done = tried = 0
    for row in rows:
        if limit is not None and tried >= limit:
            break
        if auto and row["pending_reason"] == "review_failed" and \
                row["review_attempts"] >= cfg.reviewer.max_review_attempts:
            continue
        text = store.review_input(row)
        rid = row["release_id"]
        if len(text) > cap:
            if auto:
                explain = guard.cap_explain() if guard is not None else f"cap {cap}"
                store.park_for_review(conn, rid, "too_large", f"needs {len(text)} chars; {explain}", text)
            continue
        tried += 1
        if not _attempt_review(cfg, conn, rvw, rid, row["package"], row["version"], row["triage_score"],
                               _rules_from_json(row["triage_rules"]), reviewer.refresh_marker(text), guard):
            break
        if store.get_stage(conn, row["package"], row["version"]) != "pending_review":
            done += 1
    return done



def _fetch_one(cfg, rel):
    """Worker half of the pipeline — runs OFF the main thread. Does NO sqlite and NO notifier work
    (sqlite is single-threaded), only network + in-memory extraction (incl. PyPI-baseline resolution).
    Returns the ArtifactSet, None (no sdist), or the Exception it caught, for the main thread to map."""
    try:
        return fetcher.fetch_artifacts(cfg, rel)
    except Exception as e:        # incl. RefusedToFetch/RefusedToExtract — mapped on the main thread
        return e


_REFUSALS = {
    "decompressed-size": "it unpacks to more than the size limit",
    "members": "it has more files than the limit",
    "member-name": "a file path is longer than the limit",
    "member-size": "one file is over the size limit",
    "total-size": "its files add up to more than the size limit",
    "download-size": "the download is over the size limit",
}


def _refusal_note(action: str, reason: str) -> str:
    why = _REFUSALS.get(reason) or ("it is not a readable gzip tarball" if reason.startswith("bad-archive") else "")
    return (f"UNREVIEWED: pydiffwatch refused to {action} ({reason}{': ' + why if why else ''}), so nothing "
            f"in it was scanned. Oversized or malformed archives can hide a payload from scanners. "
            f"Needs manual review.")


def _queue_refusal(cfg, conn, rid, rel, note):
    """Never unpacked, so never scanned: queue it for a human (`pending`) and say why in the alert."""
    v = Verdict(rel.package, rel.version, "suspicious", 0.0, [], False, confidence=0.0, attack_type="none",
                reasoning=note, cited_hunk="", recommended_action="monitor", model="none")
    store.record_verdict(conn, rid, v)
    notifier.emit(cfg, conn, dataclasses.replace(v, classification="suspicious-heuristic"), rid)


def _process_fetched(cfg, conn, rvw, ruleset, rel, result, offline=False, guard=None) -> bool:
    """Main-thread half: record the release, map a completed fetch `result` (ArtifactSet | None |
    Exception) to a stage, diff/triage/review, emit alerts. ALL sqlite + notifier work happens here.
    Returns True iff the release reached a terminal stage."""
    rid = store.record_release(conn, rel.package, rel.version, rel.serial, False, None, "sdist")
    if isinstance(result, fetcher.RefusedToFetch):
        store.update_stage(conn, rid, "refused_to_fetch")
        if not str(result).startswith("quarantined"):   # confirmed malware needs no second look
            _queue_refusal(cfg, conn, rid, rel, _refusal_note("download it", str(result)))
        return True   # deterministic refusal (over-size) — terminal
    if isinstance(result, fetcher.RefusedToExtract):
        store.update_stage(conn, rid, "refused_to_extract")
        _queue_refusal(cfg, conn, rid, rel, _refusal_note("unpack its sdist", str(result)))
        return True   # terminal: permanent suspicious decision recorded
    if isinstance(result, fetcher.MetadataGone):
        # PyPI pulls malware fast; a release gone before we read it is worth a look, and never a cursor pin.
        store.update_stage(conn, rid, "metadata_gone")
        notifier.emit(cfg, conn, Verdict(rel.package, rel.version, "suspicious-heuristic", 0.0, [], False,
                      confidence=0.0, attack_type="none", cited_hunk="", model="none",
                      reasoning="removed from PyPI before it could be scanned (its metadata returns 404)"), rid)
        return True
    if isinstance(result, fetcher.MetadataUnavailable):
        stage = store.note_metadata_failure(conn, rid, str(result))
        logger.warning("metadata download failed for %s==%s (%s): %s", rel.package, rel.version, stage, result)
        return True   # retried from the release row on later ticks; the cursor moves on
    if isinstance(result, Exception):
        logger.warning("fetch_failed for %s==%s; will retry next tick", rel.package, rel.version)
        store.update_stage(conn, rid, "fetch_failed")
        return False  # non-terminal: cursor must not advance past this release
    if result is None:
        store.update_stage(conn, rid, "no_sdist")   # no sdist for this version — permanent
        return True
    store.set_baseline(conn, rid, result.prior_version, result.is_new_package)
    if result.prior_error:
        store.set_fetch_note(conn, rid, result.prior_error)
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
        ev = reviewer.build_evidence(d, tr, max_chars=cfg.evidence_max_chars) if tr.escalate else None
        if ev:      # below the review threshold nobody acts on the release, so its code isn't kept
            store.update_evidence(conn, rid, ev)
        if tr.escalate:
            _review_escalated(cfg, conn, rvw, d, tr, rid, offline=offline, guard=guard)
        return True   # terminal: an unfinished LLM review is parked in the pending-review queue
    except Exception:
        logger.exception("processing failed for %s==%s; will retry next tick", rel.package, rel.version)
        store.update_stage(conn, rid, "fetch_failed")
        return False  # non-terminal: cursor must not advance past this release


def _retry_metadata(cfg, conn, rvw, ruleset, offline, guard):
    """Re-fetch releases whose metadata download failed on an earlier tick. They are behind the cursor
    already, so a result here never gates it."""
    due = [NewRelease(r["package"], r["version"], r["serial"]) for r in store.metadata_retries_due(conn)]
    with ThreadPoolExecutor(max_workers=max(1, cfg.fetch_concurrency)) as ex:
        for rel, result in zip(due, ex.map(lambda r: _fetch_one(cfg, r), due)):
            if not _process_fetched(cfg, conn, rvw, ruleset, rel, result, offline, guard):
                # A later step failed transiently. The changelog won't bring this release back, so it
                # stays in this queue (and counts toward the give-up) rather than sit in fetch_failed.
                rid = store.record_release(conn, rel.package, rel.version, rel.serial, False, None, "sdist")
                store.note_metadata_failure(conn, rid, f"retry failed after metadata: {type(result).__name__}")


def seed_now(cfg: Config):
    """Set the cursor to PyPI's current serial so monitoring starts from now (no historical crawl).
    Returns the seeded serial, or None if PyPI's current serial could not be read."""
    conn = store.connect(cfg); store.init_schema(conn)
    s = ingest.current_serial(cfg)
    if s is not None:
        store.set_last_serial(conn, s)
    return s


def run_once(cfg: Config, *, seed_if_fresh: bool = True, recent: int | None = None) -> int:
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
            if not recent:
                store.set_last_serial(conn, now_serial)
                logger.info("fresh cursor seeded to PyPI serial %d; monitoring starts now", now_serial)
                return 0
            last = max(now_serial - recent, 0)      # start N changelog events back and scan them this tick
            store.set_last_serial(conn, last)
            print(f"[pydiffwatch] starting {recent:,} PyPI changelog events back (serial {last:,}); "
                  f"catching up to now", flush=True)
        rvw = _build_reviewer(cfg)
        ruleset = _load_ruleset(cfg)
        offline = False
        guard = None
        if rvw is not None:
            reachable, label = _probe_reviewer(cfg)
            offline = reachable is False
            if offline:
                waiting = sum(store.pending_review_counts(conn).values())
                msg = (f"[pydiffwatch] WARNING: reviewer endpoint {label} is unreachable. Scanning continues; "
                       f"flagged releases are queued for LLM review ({waiting} waiting). Start the model "
                       f"server, or point [reviewer] at a reachable endpoint or a remote provider.")
                print(msg, flush=True)
                logger.warning(msg)
            else:
                guard = guard_mod.ReviewerGuard(cfg, rvw.backend, conn)
                guard.begin_batch()
                drain_pending(cfg, conn, rvw, auto=True, limit=cfg.reviewer.max_pending_per_tick, guard=guard)
        _retry_metadata(cfg, conn, rvw, ruleset, offline, guard)
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
                        terminal = _process_fetched(cfg, conn, rvw, ruleset, rel, futs[i].result(), offline, guard)
                    if terminal and not blocked:
                        advance_to = rel.serial
                    else:
                        blocked = True  # stop advancing past the first non-terminal release
        store.set_last_serial(conn, advance_to)
        try:
            store.maybe_prune(conn, cfg.retention_days, cfg.prune_every_hours * 3600, time.time())
        except sqlite3.Error:
            logger.exception("automatic prune failed; scanning continues")
        return len(releases)
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN); lock.close()


def _rules_from_json(s):
    return [FiredRule(r["rule"], r["weight"], r["file"], tuple(r["lines"])) for r in json.loads(s or "[]")]


def review_pending(cfg: Config, reasons=None, limit=None):
    """Drain the LLM-review queue with this config's reviewer (e.g. a larger-context model for
    too_large). Takes no scan lock: the per-tick auto-drain covers different reasons by default."""
    conn = store.connect(cfg); store.init_schema(conn)
    try:
        rvw = _build_reviewer(cfg)
        if rvw is None:
            return 0, store.pending_review_counts(conn)
        gd = guard_mod.ReviewerGuard(cfg, rvw.backend, conn)
        gd.begin_batch()
        n = drain_pending(cfg, conn, rvw, auto=False, reasons=reasons, limit=limit, guard=gd)
        return n, store.pending_review_counts(conn)
    finally:
        conn.close()


def metadata_retry_counts(cfg: Config) -> dict:
    conn = store.connect(cfg); store.init_schema(conn)
    try:
        return store.metadata_retry_counts(conn)
    finally:
        conn.close()


def prune(cfg: Config) -> int:
    """Shrink the database now (run/watch also do it daily); returns the bytes freed."""
    def size():
        return sum(p.stat().st_size for p in cfg.db_path.parent.glob(cfg.db_path.name + "*"))
    before = size()
    conn = store.connect(cfg); store.init_schema(conn)
    try:
        store.prune(conn, cfg.retention_days)
    finally:
        conn.close()
    return before - size()


def pending_review_counts(cfg: Config) -> dict:
    conn = store.connect(cfg); store.init_schema(conn)
    try:
        return store.pending_review_counts(conn)
    finally:
        conn.close()


def list_pending(cfg: Config):
    """Suspicious LLM verdicts awaiting adjudication. Each item carries the model's verdict plus the
    stored payload evidence (or the diff re-fetched from PyPI when evidence is absent on older rows)."""
    conn = store.connect(cfg); store.init_schema(conn)
    ruleset = _load_ruleset(cfg)
    items = []
    for row in store.pending_adjudication(conn):
        stored = store.evidence_text(row["evidence"])
        diff_text, err = stored, None
        if row["stage"] in ("refused_to_extract", "refused_to_fetch"):
            err = "refused, never scanned (see reason); inspect it by hand"
        elif not stored:                                  # older row with no captured payload -> re-fetch
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


def _cursor(cfg) -> int:
    conn = store.connect(cfg); store.init_schema(conn)
    try:
        return store.get_last_serial(conn)
    finally:
        conn.close()


def _behind(cfg, before: int) -> bool:
    """True when the tick moved the cursor and at least max_releases_per_run PyPI changelog events are
    still waiting. A pinned cursor (a release that keeps failing to fetch) is never "behind": retrying it
    back-to-back would hammer PyPI."""
    after = _cursor(cfg)
    if after <= before:
        return False
    head = ingest.current_serial(cfg)
    return head is not None and head - after >= cfg.max_releases_per_run


def watch(cfg: Config, interval: int = 300, out_path=None, iterations=None, sleep_fn=None, recent=None):
    """Daemon loop: scan one tick, refresh the dashboard, sleep, repeat until Ctrl-C. While a backlog is
    waiting (a --recent start, or a restart after downtime) the next tick starts at once instead.
    A failed scan is logged and skipped (the daemon stays up); the dashboard is
    refreshed every tick so 'last poll' / reachability stay current. `iterations`
    and `sleep_fn` exist for tests; in production both default to forever / time.sleep."""
    import time
    sleep_fn = sleep_fn or time.sleep
    n = 0
    try:
        while iterations is None or n < iterations:
            before = _cursor(cfg)
            try:
                run_once(cfg, recent=recent)
            except Exception:
                logger.exception("watch: scan tick failed; daemon continuing")
            export_dashboard(cfg, out_path=out_path)
            n += 1
            if iterations is not None and n >= iterations:
                break
            if not _behind(cfg, before):
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


def guard_status(cfg: Config):
    """The reviewer guard's view of the endpoint (breaker, measured speed, input cap) from stored stats;
    sends nothing to the endpoint. None when the reviewer is disabled."""
    if not cfg.reviewer_enabled:
        return None
    conn = store.connect(cfg); store.init_schema(conn)
    try:
        return guard_mod.ReviewerGuard(cfg, None, conn).status()
    finally:
        conn.close()


def export_dashboard(cfg: Config, out_path=None, generated_at: str = ""):
    from pathlib import Path
    out = Path(out_path) if out_path else cfg.db_path.parent / "dashboard.html"
    conn = store.connect(cfg); store.init_schema(conn)
    try:
        rows = [dict(r) for r in store.all_verdicts(conn)]
        cur = store.get_cursor(conn)
        releases_total = store.count_releases(conn)
        pending_review = store.pending_review_counts(conn)
    finally:
        conn.close()
    reachable, reviewer_label = _probe_reviewer(cfg)
    age, stale = _poll_age(cur["updated_at"] if cur else None)
    status = {
        "last_serial": cur["last_serial"] if cur else None,
        "last_poll_age": age, "stale": stale,
        "releases_total": releases_total, "verdicts_total": len(rows),
        "flagged_total": sum(1 for r in rows if (r.get("classification") or "").lower() in _FLAGGED),
        "reviewer": reviewer_label, "model_reachable": reachable, "pending_review": pending_review,
        "guard": guard_status(cfg),
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
