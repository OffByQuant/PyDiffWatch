"""ReviewerGuard: decides whether a review may be sent to the model endpoint now, and how large it may be.

A guard is rebuilt at the start of every batch from its reviewer_stats row, so the measured speed and the
breaker state survive restarts (a cron-driven `run` is a new process every tick)."""
import logging
import time

from . import hostmem, notifier, store
from .backends import ReviewUnavailable
from .reviewer import SYSTEM_PROMPT

logger = logging.getLogger(__name__)

MIN_SAMPLE_TOKENS = 2000     # smaller prompts are dominated by fixed overhead, not reading speed
COLD_START_CAP = 40_000      # chars allowed per review until the endpoint's speed is measured
DEFAULT_CPT = 3.4            # chars per token, typical of review inputs
EWMA = 0.3
PROBE_TEXT = "Reply with OK."
CALIBRATION_TEXT = "The quick brown fox jumps over the lazy dog. " * 400   # ~4k tokens; never package content


def _rate(usage, secs, input_chars):
    """Input-reading speed (tokens/s) from one request, or None if overhead would dominate it."""
    if usage and usage.get("prompt_per_second"):
        if usage.get("prompt_n", MIN_SAMPLE_TOKENS) < MIN_SAMPLE_TOKENS:
            return None
        return float(usage["prompt_per_second"])
    tokens = usage["prompt_tokens"] if usage else input_chars / DEFAULT_CPT
    if tokens < MIN_SAMPLE_TOKENS or secs <= 0:
        return None
    return tokens / secs


def describe(status):
    """One line for `pending` and the dashboard."""
    state = {"closed": "reviews on", "open": "reviews paused (timeout)",
             "degraded": "reviews paused (model degrading)"}.get(status["state"], status["state"])
    speed = f"{status['tok_s']:.0f} tok/s" if status.get("tok_s") else "speed not measured yet"
    line = f"{state} · {speed} · input cap {status['cap_chars']:,} chars"
    if status.get("host_memory"):
        line += f" · host memory: {status['host_memory']}"
    return line


class ReviewerGuard:
    def __init__(self, cfg, backend, conn, *, clock=time.time, memory="auto", out=None):
        rc = cfg.reviewer
        self.cfg, self.rc, self.backend, self.conn, self.clock = cfg, rc, backend, conn, clock
        self.memory = hostmem.for_config(cfg) if memory == "auto" else memory
        self.out = out or (lambda msg: print(msg, flush=True))
        self.endpoint = rc.base_url if rc.provider == "openai" else rc.provider
        self.model = rc.model
        self.measured = rc.provider == "openai"   # hosted APIs read input far faster than any timeout here
        s = store.get_reviewer_stats(conn, self.endpoint, self.model) or {}
        self.tok_s = s.get("tok_s")
        self.cpt = s.get("chars_per_token") or DEFAULT_CPT
        self.samples = s.get("samples") or 0
        self.state = s.get("state") or "closed"
        self.detail = s.get("detail") or ""
        self.paused_until = s.get("paused_until") or 0.0
        self.slow_streak = s.get("slow_streak") or 0
        self.ctx_tokens = None
        self._esc_ctx_tokens = {}
        self.warned_no_room = False

    def begin_batch(self):
        """Once per batch, before any review. A paused endpoint gets a health probe; an unmeasured one gets
        a calibration request, sent after a probe so a model llama-swap is still loading isn't timed."""
        if self.state != "closed":
            if self.clock() < self.paused_until:
                return
            try:
                self.backend.ping(PROBE_TEXT, timeout=self.rc.probe_timeout)
            except ReviewUnavailable as e:
                self._say(f"reviewer endpoint {self.endpoint} is still not answering ({e}); reviews stay paused")
                return
            self._set("closed", "")
            self._say(f"reviewer endpoint {self.endpoint} answered the health probe; reviews resume")
        if not self.measured:
            return
        if self.ctx_tokens is None:
            self.ctx_tokens = self.backend.context_length()
        if self.tok_s is None:
            self._calibrate()

    def ctx_tokens_for(self, model):
        """The context window for `model` — the primary model's is `ctx_tokens` (looked up in
        begin_batch); any other model (e.g. an escalation model on the same endpoint) is looked up the
        same way, on demand, and cached here for the guard's lifetime. None when unmeasured or the
        endpoint can't report it (spec C2: the reviewer then sends the config value unclamped)."""
        if model == self.backend.primary_model:
            return self.ctx_tokens
        if not self.measured:
            return None
        if model not in self._esc_ctx_tokens:
            self._esc_ctx_tokens[model] = self.backend.context_length(model)
        return self._esc_ctx_tokens[model]

    def _calibrate(self):
        try:
            self.backend.ping(PROBE_TEXT, timeout=self.rc.probe_timeout)
            t = self.clock()
            usage = self.backend.ping(CALIBRATION_TEXT, timeout=self.rc.probe_timeout)
            secs = self.clock() - t
        except ReviewUnavailable as e:
            logger.warning("reviewer calibration failed for %s: %s", self.endpoint, e)
            return
        rate = _rate(usage, secs, len(CALIBRATION_TEXT))
        if rate:
            self.tok_s = rate
            self._save()
            self.out(f"[pydiffwatch] reviewer endpoint {self.endpoint} reads ~{rate:.0f} tokens/s; "
                     f"review inputs capped at {self.input_cap_chars():,} chars")

    def admit(self):
        """None if a review may be sent now; otherwise why not (stored as the model_busy detail)."""
        self._refresh()           # another process (review-pending, the watch loop) may have opened the breaker
        if self.state != "closed":
            return self.detail
        if self.memory is not None:
            why = self.memory.pressure()
            if why:
                return f"host memory: {why}"
        return None

    def _cap_terms(self):
        """Each limit on the review input as (chars, what sets it); the cap is the smallest."""
        terms = [(self.rc.max_input_chars, "reviewer.max_input_chars")]
        if not self.measured:
            return terms
        if self.tok_s is None:
            terms.append((COLD_START_CAP, "cold-start cap until this endpoint's speed is measured"))
        else:
            terms.append((int(self.tok_s * self.rc.timeout * self.rc.budget_safety * self.cpt),
                          f"≈{self.tok_s:.0f} tok/s × {self.rc.timeout:.0f}s × {self.rc.budget_safety}"))
        if self.ctx_tokens:
            # Reserve room for the verdict, but never the whole window: a 32k-context endpoint with the default
            # 32,000-token max_output_tokens would otherwise get a cap of 0 and never review anything.
            reserve = min(self.rc.max_output_tokens, self.ctx_tokens // 4)
            room = self.ctx_tokens - reserve - len(SYSTEM_PROMPT) / DEFAULT_CPT
            if room <= 0 and not self.warned_no_room:
                self.warned_no_room = True
                self._say(f"reviewer endpoint {self.endpoint}'s {self.ctx_tokens:,}-token context window leaves no "
                          f"room for review input; use a model with a larger context")
            terms.append((int(room * self.cpt), f"{self.ctx_tokens:,}-token context window"))
        return terms

    def input_cap_chars(self):
        return max(min(c for c, _ in self._cap_terms()), 0)

    def cap_is_provisional(self):
        """True while the cap is the cold-start cap: the endpoint's speed isn't measured yet, so an input over
        it may well fit once it is."""
        return self.measured and self.tok_s is None and self.input_cap_chars() == COLD_START_CAP

    def cap_explain(self):
        cap, why = min(self._cap_terms(), key=lambda t: t[0])
        return f"this endpoint's cap is {max(cap, 0):,} chars ({why})"

    def record_success(self, usage, secs, input_chars):
        if not self.measured:
            return
        rate = _rate(usage, secs, input_chars)
        if rate is None:
            return
        if self.tok_s is not None and rate < self.rc.slowdown_ratio * self.tok_s:
            if not usage or not usage.get("prompt_per_second"):
                return    # wall-clock time includes output and model loading: not evidence of a degrading server
            self.slow_streak += 1                     # slow samples never lower the baseline
            if self.slow_streak >= 2:
                pct = 100 * rate / self.tok_s
                self._set("degraded", "degraded", self.clock() + self.rc.degraded_pause_s)
                msg = self._say(f"reviewer endpoint {self.endpoint} is running at {pct:.0f}% of its measured speed — "
                                f"the model server is likely short on memory or swapping; consider restarting it. "
                                f"Reviews pause for {self.rc.degraded_pause_s:.0f}s")
                notifier.post_webhook(self.cfg, msg)
            else:
                self._save()
            return
        self.slow_streak = 0
        self.tok_s = rate if self.tok_s is None else (1 - EWMA) * self.tok_s + EWMA * rate
        if usage and usage.get("prompt_tokens", 0) >= MIN_SAMPLE_TOKENS:
            self.cpt = (1 - EWMA) * self.cpt + EWMA * (input_chars / usage["prompt_tokens"])
        self.samples += 1
        self._save()

    def record_timeout(self):
        self._set("open", "breaker open after timeout")
        self._say(f"reviewer endpoint {self.endpoint} timed out; no more reviews this batch. The next batch "
                  f"probes it first (the server may still be working on the abandoned request)")

    def status(self):
        return {"state": self.state, "detail": self.detail,
                "tok_s": round(self.tok_s, 1) if self.tok_s else None,
                "cap_chars": self.input_cap_chars(),
                "host_memory": (self.memory.pressure() or "ok") if self.memory is not None else None}

    def _set(self, state, detail, paused_until=0.0):
        self.state, self.detail, self.paused_until = state, detail, paused_until
        if state == "closed":
            self.slow_streak = 0
        self._save(transition=True)

    def _refresh(self):
        s = store.get_reviewer_stats(self.conn, self.endpoint, self.model)
        if s:
            self.state, self.detail, self.paused_until = s["state"] or "closed", s["detail"] or "", s["paused_until"] or 0.0

    def _save(self, transition=False):
        if not transition:
            self._refresh()       # only a state transition may change the breaker; a stats update keeps the stored one
        store.save_reviewer_stats(self.conn, self.endpoint, self.model, tok_s=self.tok_s, chars_per_token=self.cpt,
                                  samples=self.samples, state=self.state, detail=self.detail,
                                  paused_until=self.paused_until, slow_streak=self.slow_streak)

    def _say(self, msg):
        full = f"[pydiffwatch] WARNING: {msg}"
        self.out(full)
        logger.warning(full)
        return full
