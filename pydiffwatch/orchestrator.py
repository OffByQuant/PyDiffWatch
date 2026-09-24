import dataclasses, datetime, fcntl, json, logging, math, os, sqlite3, time
from concurrent.futures import ThreadPoolExecutor
from . import ingest, fetcher, differ, engine, rules, notifier, store, reviewer, egress, dashboard, quarantine
from . import guard as guard_mod
from .config import Config
from .models import Verdict, NewRelease, FiredRule

logger = logging.getLogger(__name__)

# Stages that represent a completed analysis or permanent decision; skipped on future ticks.
# pending_review is terminal for the cursor: the LLM-review queue retries it, not the scan. Likewise
# metadata_retry: a release whose metadata or sdist download, or diff/triage, failed is retried from its
# release row (bounded, then gave_up), not the changelog. So is no_sdist_wait: a wheel-only release re-checked
# for a late sdist once wheel_only_grace_minutes are over.
TERMINAL = {"triaged", "alerted", "reviewed", "new_package_skipped", "needs_adjudication",
            "refused_to_extract", "no_sdist", "refused_to_fetch", "pending_review",
            "metadata_gone", "metadata_retry", "gave_up", "no_sdist_wait"}


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



def _clip(text, limit=300) -> str:
    return text if len(text) <= limit else text[:limit].rstrip() + "…"


def _clip_files(paths, limit=300) -> str:
    return _clip(", ".join(paths), limit)


def _record(cfg, conn, rid, verdict, score, dropped=()):
    store.clear_pending(conn, rid)
    # spec U2: a benign verdict is not final when the input cap dropped a file that carried fired-rule
    # weight — the model never saw it, so route to adjudication instead of saving silently.
    if verdict.classification == "benign" and dropped:
        note = f"reviewed partially: {_clip_files(dropped)} not shown"
        reasoning = f"{note}. Model: {verdict.reasoning}" if verdict.reasoning else note
        v = dataclasses.replace(verdict, reasoning=reasoning)
        store.record_verdict(conn, rid, v)
        store.update_stage(conn, rid, "needs_adjudication", score, None)  # -> `pydiffwatch pending`
        notifier.emit(cfg, conn, dataclasses.replace(v, classification="suspicious-heuristic"), rid,
                     dedupe_suffix="partial-review")                      # one alert; a person looks at it
        return
    store.record_verdict(conn, rid, verdict)
    # Route by the model's classification. A `suspicious` verdict is queued for human adjudication — it
    # is NOT alerted. benign is saved silently; malicious (or any unexpected class) alerts immediately.
    if verdict.classification == "benign":
        store.clear_evidence(conn, rid)                                   # kept only where a person may act
        store.update_stage(conn, rid, "reviewed", score, None)            # saved silently, no alert
    elif verdict.classification == "suspicious":
        store.update_stage(conn, rid, "needs_adjudication", score, None)  # -> `pydiffwatch pending`
        if verdict.model == "none":   # nothing flagged could be shown to the model: warn, as heuristic-only does
            _alert_unscanned(cfg, conn, rid, verdict.package, verdict.version, verdict.reasoning,
                             stage="no_content", score=score, fired_rules=verdict.fired_rules, queue=False)
    else:                                                                 # malicious / unexpected
        notifier.emit(cfg, conn, verdict, rid)
        store.update_stage(conn, rid, "reviewed", score, None)


def _max_tokens_for(cfg, guard, text, model) -> int:
    """spec C2: clamp reviewer.max_output_tokens to what's left of `model`'s own context window once the
    prompt is accounted for, so an OpenAI-compatible endpoint (e.g. vLLM) doesn't reject prompt + max_tokens
    > max_model_len with HTTP 400. Looked up per model (an escalation model on the same endpoint can have a
    smaller window than the primary) via guard.ctx_tokens_for. Unclamped (the config value) when the
    window isn't known, and never above the config value even when the floor would otherwise exceed it."""
    max_output_tokens = cfg.reviewer.max_output_tokens
    if guard is None:
        return max_output_tokens
    ctx_tokens = guard.ctx_tokens_for(model)
    if ctx_tokens is None:
        return max_output_tokens
    prompt_estimate = math.ceil((len(reviewer.SYSTEM_PROMPT) + len(text)) / guard.cpt)
    return min(max_output_tokens, max(256, ctx_tokens - prompt_estimate - 64))


def _attempt_review(cfg, conn, rvw, rid, package, version, score, fired_rules, text, guard=None,
                    dropped=()) -> bool:
    """One review attempt; on failure the release is (re)parked with the reason. Returns False when no more
    reviews should be sent now (endpoint unreachable, guard deferring, or the guard's breaker just opened),
    so a drain stops instead of hammering the server. `dropped`: weighted files this text's cap dropped
    (spec U2), carried through to _record — from `rvw.dropped_files` on a fresh review, or recovered
    from the stored text via reviewer.dropped_from_text() when drain_pending re-drives a parked row."""
    if guard is not None:
        why = guard.admit()
        if why:
            _park_auto(conn, rid, "model_busy", why, text)
            return False
    attempt = store.review_attempts(conn, rid) + 1
    t0 = time.monotonic()
    try:
        with _review_slot(cfg):
            verdict = rvw.review_text(package, version, score, fired_rules, text, attempt=attempt,
                                      max_tokens_for=lambda model: _max_tokens_for(cfg, guard, text, model))
    except reviewer.ReviewUnavailable as e:
        logger.warning("LLM review failed for %s==%s (attempt %d): %s", package, version, attempt, e)
        if _endpoint_down(e):     # an outage, not this release's fault: don't spend an attempt
            _park_auto(conn, rid, "endpoint_unreachable", str(e), text)
            return False
        _review_failed(cfg, conn, rid, package, version, score, fired_rules, text, str(e))
        if guard is not None and _is_timeout(e):
            guard.record_timeout()
            return False
        return True
    except Exception as e:        # D20: e.g. a malformed reply. A failed attempt of this release, never a failed tick
        logger.exception("LLM review raised for %s==%s (attempt %d)", package, version, attempt)
        _review_failed(cfg, conn, rid, package, version, score, fired_rules, text, f"{type(e).__name__}: {e}")
        return True
    if guard is not None and verdict.model == rvw.backend.primary_model:
        # Only a single primary-model call is a speed sample: an escalation spans two models (and a swap).
        # prompt_tokens cover the system prompt as well as the package content, so the chars must too.
        guard.record_success(getattr(rvw.backend, "last_usage", None), time.monotonic() - t0,
                             len(reviewer.SYSTEM_PROMPT) + len(text))
    _record(cfg, conn, rid, verdict, score, dropped=dropped)
    return True


def _park(conn, rid, reason, detail, text):
    """park_for_review; text None (the stored input couldn't be read back) keeps the stored input."""
    if text is None:
        store.set_pending_reason(conn, rid, reason, detail)
    else:
        store.park_for_review(conn, rid, reason, detail, text)


def _park_auto(conn, rid, reason, detail, text):
    """Park for a reason the auto-drain retries on its own. A stale UNREVIEWED verdict (e.g. from an earlier
    too_large park) goes: the release is not waiting for a person while the auto-drain owns it."""
    _park(conn, rid, reason, detail, text)
    store.clear_unscanned_verdict(conn, rid)


def _review_failed(cfg, conn, rid, package, version, score, fired_rules, text, err):
    """Count a failed review attempt and park it as review_failed. With attempts left the auto-drain retries
    it; once they are used up (>=, so a lowered max_review_attempts counts too) it warns, once."""
    n = store.bump_review_attempts(conn, rid)
    if n >= cfg.reviewer.max_review_attempts:      # the auto-drain stops retrying it from here on
        _park(conn, rid, "review_failed", f"{n} failed attempt(s): {err}", text)
        _alert_review_exhausted(cfg, conn, rid, package, version, n, err, score, fired_rules)
    else:
        _park_auto(conn, rid, "review_failed", f"{n} failed attempt(s): {err}", text)


def _alert_review_exhausted(cfg, conn, rid, package, version, n, err, score, fired_rules):
    _alert_unscanned(cfg, conn, rid, package, version,
                     f"UNREVIEWED: the model failed to review it {n} times (last error: {err}); "
                     f"retries are used up. Run `review-pending` to try again, e.g. with another "
                     f"model. Not scanned. Needs manual review.",
                     stage="review_failed", score=score, fired_rules=fired_rules)


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
        # Over the provisional cold-start cap it may fit once the endpoint is measured: no "too large" claim
        # yet (the auto-drain makes it then), only the heuristic alert any other park gets.
        provisional = guard is not None and guard.cap_is_provisional()
        _park_too_large(cfg, conn, rid, d.package, d.version, tr.score, tr.fired_rules, detail, e.text,
                        alert=not provisional)
        if provisional:
            _alert_heuristic(cfg, conn, rid, d.package, d.version, tr.score, tr.fired_rules)
        return      # one alert: the unscanned one (with the score and rules), or the heuristic one
    else:
        dropped = getattr(rvw, "dropped_files", ())   # spec U2: weighted files prepare()'s cap dropped
        if offline:
            _park_auto(conn, rid, "endpoint_unreachable", "reviewer endpoint unreachable", text)
        else:
            # Queued before the model call, which can take minutes: a kill mid-review leaves the release in the
            # auto-drain queue rather than at `triaged`, which no tick revisits. A finished review un-parks it.
            _park_auto(conn, rid, "in_review", "the review was interrupted before it finished", text)
            _attempt_review(cfg, conn, rvw, rid, d.package, d.version, tr.score, tr.fired_rules, text, guard,
                            dropped=dropped)
    if store.get_stage(conn, d.package, d.version) == "pending_review":
        _alert_heuristic(cfg, conn, rid, d.package, d.version, tr.score, tr.fired_rules)


def _alert_heuristic(cfg, conn, rid, package, version, score, fired_rules):
    """Not reviewed yet: alert on the heuristic now rather than wait for the queue to drain."""
    notifier.emit(cfg, conn, Verdict(package, version, "suspicious-heuristic", score, fired_rules, False), rid)


def drain_pending(cfg, conn, rvw, *, auto: bool, reasons=None, limit=None, guard=None,
                  clock=time.monotonic) -> int:
    """Review parked releases. auto (each tick): model_busy first, then unreachable-endpoint parks, failed
    reviews with attempts left, and too_large rows that now fit. Manual (`review-pending`): by default oversized
    releases and exhausted retries — run it with a larger-context model config. Inputs over this endpoint's cap are skipped
    (auto: re-parked as too_large). `limit` caps attempts, not successes. Returns the number reviewed.
    The auto-drain runs before the retry sweep and ingest, holding the scan lock, so it has a time budget
    (reviewer.timeout, one first attempt's worth): no new review starts once it is spent, and the rest wait for
    the next tick. A review already started runs to its own timeout."""
    if auto:
        reasons = ("model_busy", "in_review", "endpoint_unreachable", "review_failed")
    elif not reasons:
        reasons = ("too_large", "review_failed")
    cap = guard.input_cap_chars() if guard is not None else cfg.reviewer.max_input_chars
    provisional = guard is not None and guard.cap_is_provisional()
    # No stored input here: it is read only for a row that is reviewed. The auto-drain skips exhausted retries.
    rows = store.pending_reviews(conn, reasons, max_attempts=cfg.reviewer.max_review_attempts if auto else None,
                                 with_input=False)
    if auto:      # oversized for an earlier cap (cold start, a smaller max_input_chars) but fits this one
        rows += store.pending_reviews(conn, ("too_large",), max_chars=cap, with_input=False)
        if not provisional:   # parked silently over the cold-start cap, and over the measured one too: warn now
            rows += store.pending_reviews(conn, ("too_large",), over_chars=cap, without_verdict=True,
                                          with_input=False)
    rows = sorted(rows,
                  key=lambda r: (r["pending_reason"] != "model_busy", r["release_id"]))
    done = tried = 0
    t0 = clock()
    for n, row in enumerate(rows):
        if limit is not None and tried >= limit:
            break
        if auto and clock() - t0 >= cfg.reviewer.timeout:
            logger.warning("review queue used its %.0fs budget; %d release(s) wait for the next tick",
                           cfg.reviewer.timeout, len(rows) - n)
            break
        try:
            attempted, go_on = _drain_one(cfg, conn, rvw, row, auto=auto, cap=cap, provisional=provisional,
                                          guard=guard)
        except Exception as e:   # a corrupt row or a bug on this input: its failed attempt, never a stalled tick
            logger.exception("review queue: %s==%s failed", row["package"], row["version"])
            try:
                rules = _rules_from_json(row["triage_rules"])
            except Exception:
                rules = []
            _review_failed(cfg, conn, row["release_id"], row["package"], row["version"], row["triage_score"],
                           rules, None, f"{type(e).__name__}: {e}")
            attempted, go_on = True, True
        tried += attempted
        if not go_on:
            break
        if attempted and store.get_stage(conn, row["package"], row["version"]) != "pending_review":
            done += 1
    return done


def _drain_one(cfg, conn, rvw, row, *, auto, cap, provisional, guard):
    """One drain_pending row. Returns (attempted: a review was tried, go_on: keep draining)."""
    if auto and row["pending_reason"] == "review_failed" and \
            row["review_attempts"] >= cfg.reviewer.max_review_attempts:
        if not row["has_verdict"]:     # e.g. max_review_attempts was lowered after its last attempt
            _alert_review_exhausted(cfg, conn, row["release_id"], row["package"], row["version"],
                                    row["review_attempts"], (row["pending_detail"] or "").split(": ", 1)[-1],
                                    row["triage_score"], _rules_from_json(row["triage_rules"]))
        return False, True
    rid = row["release_id"]
    chars = row["review_input_chars"]
    if chars > cap:
        if auto:
            explain = guard.cap_explain() if guard is not None else f"cap {cap}"
            # Over the provisional cold-start cap it may fit once the endpoint is measured: park silently.
            _park_too_large(cfg, conn, rid, row["package"], row["version"], row["triage_score"],
                            _rules_from_json(row["triage_rules"]), f"needs {chars} chars; {explain}", None,
                            alert=not provisional)
        return False, True
    text = store.review_input(row, conn)
    fired_rules = _rules_from_json(row["triage_rules"])
    dropped = reviewer.dropped_from_text(fired_rules, text)   # spec U2: recovered from stored text
    go_on = _attempt_review(cfg, conn, rvw, rid, row["package"], row["version"], row["triage_score"],
                            fired_rules, reviewer.refresh_marker(text), guard, dropped=dropped)
    if row["pending_reason"] == "in_review" and \
            store.get_stage(conn, row["package"], row["version"]) == "pending_review":
        # A review interrupted by a kill, and still not done: the first-park alert it never got.
        _alert_heuristic(cfg, conn, rid, row["package"], row["version"], row["triage_score"], fired_rules)
    return True, go_on



def _fetch_one(cfg, rel, attempt=1):
    """Worker half of the pipeline — runs OFF the main thread. Does NO sqlite and NO notifier work
    (sqlite is single-threaded), only network + in-memory extraction (incl. PyPI-baseline resolution).
    Attempt k (a retry of a failed release) gets k times the package-JSON and sdist deadlines (see
    fetcher.fetch_artifacts), as review retries get timeout x attempt; attempt 1 keeps them as configured.
    Returns the ArtifactSet, a NoSdist, or the Exception it caught, for the main thread to map."""
    try:
        return fetcher.fetch_artifacts(cfg, rel, attempt=attempt)
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


def _alert_unscanned(cfg, conn, rid, package, version, note, *, stage, score=0.0, fired_rules=(),
                     queue=True) -> bool:
    """The one path for an outcome that leaves a release unscanned: alert once, and queue it for a person.

    - `note` is the alert's reasoning. By convention it starts `UNREVIEWED:` and ends `Not scanned. Needs
      manual review.` (refusals and `metadata_gone` keep their own endings).
    - `stage` names the outcome (`refused_to_fetch`, `too_large`, `gave_up`, ...). The alert is
      `suspicious-heuristic`, deduped on package|version|suspicious-heuristic|unscanned:<stage>, so it fires
      once per outcome even after the first-park heuristic alert, and never again on a re-tick.
    - `queue=True` records the UNREVIEWED verdict (`suspicious`, model `none`), so the release waits in
      `pending` until a person adjudicates it or a model review replaces the verdict. `queue=False` alerts
      only (nothing is left to review).
    - `score` / `fired_rules` carry the triage result into the alert when there is one.
    Never classifies the release `malicious`. Returns True iff the alert was new."""
    v = Verdict(package, version, "suspicious", score or 0.0, list(fired_rules), False, confidence=0.0,
                attack_type="none", reasoning=note, cited_hunk="", recommended_action="monitor", model="none")
    if queue:
        store.record_verdict(conn, rid, v)
    return notifier.emit(cfg, conn, dataclasses.replace(v, classification="suspicious-heuristic"), rid,
                         dedupe_suffix=f"unscanned:{stage}")


def _park_too_large(cfg, conn, rid, package, version, score, fired_rules, detail, text, alert=True):
    _park(conn, rid, "too_large", detail, text)
    if alert:
        _alert_unscanned(cfg, conn, rid, package, version,
                         f"UNREVIEWED: its review input is too large for the model ({detail}); run "
                         f"`review-pending` with a larger-context model. Not scanned. Needs manual review.",
                         stage="too_large", score=score, fired_rules=fired_rules)


def _process_fetched(cfg, conn, rvw, ruleset, rel, result, offline=False, guard=None) -> bool:
    """Main-thread half: record the release, map a completed fetch `result` (ArtifactSet | NoSdist |
    Exception; None is read as NoSdist) to a stage, diff/triage/review, emit alerts. ALL sqlite + notifier
    work happens here.
    Returns True iff the release reached a terminal stage; a failure is queued for retry (_retry_later),
    which is terminal for the cursor."""
    rid = store.record_release(conn, rel.package, rel.version, rel.serial, False, None, "sdist")
    was = store.get_stage(conn, rel.package, rel.version)
    if was == "no_sdist":
        store.clear_unscanned_verdict(conn, rid)   # re-scan after its sdist upload: drop the switch warning
    if isinstance(result, fetcher.RefusedToFetch):
        store.update_stage(conn, rid, "refused_to_fetch")
        if str(result).startswith("quarantined"):
            # A new release of a quarantined project: never downloaded, so never cleared either. The list
            # holds unconfirmed entries too, so this is a cue to look, not a `malicious` verdict.
            note = (f"UNREVIEWED: this project is on pydiffwatch's quarantine list "
                    f"({quarantine.reason(rel.package) or result}), so this release was not downloaded. "
                    f"Not scanned. Needs manual review.")
        else:
            note = _refusal_note("download it", str(result))
        _alert_unscanned(cfg, conn, rid, rel.package, rel.version, note, stage="refused_to_fetch")
        return True   # deterministic refusal (over-size, quarantine) — terminal
    if isinstance(result, fetcher.RefusedToExtract):
        store.update_stage(conn, rid, "refused_to_extract")
        _alert_unscanned(cfg, conn, rid, rel.package, rel.version, _refusal_note("unpack its sdist", str(result)),
                         stage="refused_to_extract")
        return True   # terminal: permanent suspicious decision recorded
    if isinstance(result, fetcher.MetadataGone):
        # PyPI pulls malware fast; a release gone before we read it is worth knowing about, and never a cursor
        # pin. Not queued: with the files gone, a person can't review it either.
        store.update_stage(conn, rid, "metadata_gone")
        _alert_unscanned(cfg, conn, rid, rel.package, rel.version,
                         "UNREVIEWED: removed from PyPI before it could be scanned (its metadata returns 404); "
                         "the files are gone, so there is nothing to review.", stage="metadata_gone", queue=False)
        return True
    if isinstance(result, Exception):   # metadata or sdist download failed (incl. a deadline expiry)
        return _retry_later(cfg, conn, rid, rel, result)
    if result is None or isinstance(result, fetcher.NoSdist):
        # A switch from an sdist (PyPI's JSON, or our own record when the owner deleted that sdist since) can
        # dodge an sdist-only scan; a package always wheel-only is silent. Wheels often upload before the sdist,
        # so a switch (or an sdist upload event the JSON doesn't show yet) waits for wheel_only_grace_minutes
        # and is re-fetched before it warns. A fetch that got this far succeeded: earlier failures stop counting.
        # A release whose re-check failed (metadata_retry, with its grace spent) is decided by the retry.
        store.clear_fetch_failures(conn, rid)
        prev = getattr(result, "switched_from", None) or store.previous_sdist_release(conn, rel.package, rel.version)
        now = time.time()
        recheck = store.recheck_at(conn, rid)
        due = was in ("no_sdist_wait", "metadata_retry") and recheck is not None and recheck <= now
        if (prev or rel.sdist_upload) and not due:
            if was != "no_sdist_wait":
                due_at = now + cfg.wheel_only_grace_minutes * 60
                store.wait_for_sdist(conn, rid, due_at)
                logger.info("%s==%s has no sdist yet; parked in no_sdist_wait until %s, then re-checked",
                            rel.package, rel.version,
                            datetime.datetime.fromtimestamp(due_at, datetime.UTC).isoformat(timespec="seconds"))
            return True
        store.update_stage(conn, rid, "no_sdist")   # terminal, unless its sdist upload event arrives later
        if prev:
            _alert_unscanned(cfg, conn, rid, rel.package, rel.version,
                             f"UNREVIEWED: switched to wheel-only: the previous release {prev} shipped an sdist and "
                             f"this one ships only wheels, which pydiffwatch does not scan. Not scanned. Needs "
                             f"manual review.", stage="no_sdist")
        return True
    store.set_baseline(conn, rid, result.prior_version, result.is_new_package)
    store.set_fetch_note(conn, rid, result.prior_error)   # None clears an earlier failure's note (D2)
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
            try:
                _review_escalated(cfg, conn, rvw, d, tr, rid, offline=offline, guard=guard)
            except Exception as e:   # D20: the scan is done, only the review failed: park it, never refetch
                logger.exception("review failed for %s==%s; parked for review", rel.package, rel.version)
                text = reviewer.build_review_input(d, tr, max_chars=cfg.reviewer.max_input_chars)
                _review_failed(cfg, conn, rid, d.package, d.version, tr.score, tr.fired_rules, text,
                               f"{type(e).__name__}: {e}")
                notifier.emit(cfg, conn, Verdict(d.package, d.version, "suspicious-heuristic",
                                                 tr.score, tr.fired_rules, False), rid)
        # Only now, with evidence and review handled, do earlier failures stop counting: a crash in any step
        # above (they parse package content) must still reach gave_up.
        store.clear_fetch_failures(conn, rid, result.prior_error)
        return True   # terminal: an unfinished LLM review is parked in the pending-review queue
    except Exception as e:
        logger.exception("processing failed for %s==%s", rel.package, rel.version)
        return _retry_later(cfg, conn, rid, rel, e)


def _retry_later(cfg, conn, rid, rel, e) -> bool:
    """Queue a failed release for retry from its row (store.note_metadata_failure: bounded, then gave_up,
    both shown by `pending`). The cursor moves on: a failure that never clears must not pin it. The move to
    gave_up alerts once, with the last error (the release's fetch_note)."""
    was = store.get_stage(conn, rel.package, rel.version)
    note = f"{type(e).__name__}: {e}"
    stage = store.note_metadata_failure(conn, rid, note)
    n = store.fetch_attempts(conn, rid)
    then = (f"giving up after {n} attempts" if stage == "gave_up" else
            f"will retry next tick (attempt {n} of {store.METADATA_ATTEMPTS})")
    logger.warning("scan failed for %s==%s (%s); %s", rel.package, rel.version, note, then)
    if stage == "gave_up" and was != "gave_up":
        _alert_unscanned(cfg, conn, rid, rel.package, rel.version,
                         f"UNREVIEWED: pydiffwatch failed to download or scan it {store.METADATA_ATTEMPTS} times "
                         f"and gave up (last error: {_clip(note)}). Not scanned. Needs manual review.", stage="gave_up")
    return True


def _retry_metadata(cfg, conn, rvw, ruleset, offline, guard, clock=time.monotonic):
    """Re-fetch and re-scan releases that failed on an earlier tick. They are behind the cursor already,
    so a result here never gates it; a repeat failure counts toward the give-up (_retry_later).
    It runs before ingest, holding the scan lock, so it has a time budget (packument_deadline_s): no new window
    of fetch_concurrency rows starts once it is spent, and the rest wait for the next tick."""
    rows = store.metadata_retries_due(conn)
    W = max(1, cfg.fetch_concurrency)
    t0 = clock()
    with ThreadPoolExecutor(max_workers=W) as ex:
        for start in range(0, len(rows), W):
            if clock() - t0 >= cfg.packument_deadline_s:
                logger.warning("retry sweep used its %.0fs budget; %d release(s) wait for the next tick",
                               cfg.packument_deadline_s, len(rows) - start)
                break
            window = [(NewRelease(r["package"], r["version"], r["serial"]), (r["fetch_attempts"] or 0) + 1)
                      for r in rows[start:start + W]]
            futs = [(rel, ex.submit(_fetch_one, cfg, rel, k)) for rel, k in window]
            for rel, fut in futs:
                _process_fetched(cfg, conn, rvw, ruleset, rel, fut.result(), offline, guard)


def seed_now(cfg: Config):
    """Set the cursor to PyPI's current serial so monitoring starts from now (no historical crawl).
    Returns the seeded serial, or None if PyPI's current serial could not be read."""
    conn = store.connect(cfg); store.init_schema(conn)
    s = ingest.current_serial(cfg)
    if s is not None:
        store.set_last_serial(conn, s)
    return s


def _to_fetch(conn, rel) -> bool:
    """Whether run_once fetches and processes this changelog item. A release not yet at a TERMINAL stage is
    fetched. An sdist upload re-scans a release left wheel-only (its wheels uploaded first); on any other
    release it is a no-op (one SELECT, no fetch), since that release's own `new release` event covers it."""
    stg = store.get_stage(conn, rel.package, rel.version)
    if rel.sdist_upload and stg in ("no_sdist", "no_sdist_wait"):
        return True
    return rel.new_release and stg not in TERMINAL


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
        prepared = [(rel, _to_fetch(conn, rel)) for rel in releases]

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
                        for i, (rel, fetch) in enumerate(window) if fetch}
                for i, (rel, fetch) in enumerate(window):
                    if not fetch:
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
        not_scanned = (row["pending_reason"] if row["stage"] == "pending_review" else row["stage"]) \
            if row["stage"] in store.UNSCANNED_STAGES else None
        if row["stage"] == "needs_adjudication" and row["model"] == "none":
            not_scanned = "no_content"          # the reviewer had nothing it could show the model
        if row["stage"] in ("refused_to_extract", "refused_to_fetch"):
            err = "refused, never scanned (see reason); inspect it by hand"
        elif not_scanned and not stored:
            err = "never scanned (see reason); inspect it by hand"
        elif not stored:                                  # older row with no captured payload -> re-fetch
            try:
                art = fetcher.fetch_artifacts(cfg, NewRelease(row["package"], row["version"], row["serial"]))
                if art is not None and not isinstance(art, fetcher.NoSdist):
                    d = differ.build_diff(art)
                    tr = engine.triage(d, cfg, ruleset)
                    diff_text = reviewer.build_review_input(d, tr, max_chars=cfg.reviewer.max_input_chars)
            except Exception as e:
                err = f"{type(e).__name__}: {e}"
        items.append({"release_id": row["release_id"], "package": row["package"], "version": row["version"],
                      "classification": row["classification"], "confidence": row["confidence"],
                      "attack_type": row["attack_type"], "reasoning": row["reasoning"],
                      "cited_hunk": row["cited_hunk"], "diff_text": diff_text, "fetch_error": err,
                      "evidence_stored": stored is not None, "not_scanned": not_scanned})
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
                if art is None or isinstance(art, fetcher.NoSdist):
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
    still waiting. A pinned cursor (the PyPI changelog call keeps failing) is never "behind": retrying it
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
            before = None
            try:    # any per-tick failure (e.g. a transient "database is locked") is logged; the daemon stays up
                before = _cursor(cfg)
                try:
                    run_once(cfg, recent=recent)
                except Exception:
                    logger.exception("watch: scan tick failed; daemon continuing")
                export_dashboard(cfg, out_path=out_path)
            except Exception:
                logger.exception("watch: tick failed; daemon continuing")
            n += 1
            if iterations is not None and n >= iterations:
                break
            try:
                behind = before is not None and _behind(cfg, before)
            except Exception:
                logger.exception("watch: backlog check failed; sleeping as usual")
                behind = False
            if not behind:
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
        "flagged_total": sum(1 for r in rows if dashboard.is_flagged(r)),
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
