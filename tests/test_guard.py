# tests/test_guard.py
import dataclasses

from pydiffwatch import guard as g, store
from pydiffwatch.backends import ReviewUnavailable
from pydiffwatch.config import Config


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


class Backend:
    """ping() advances the clock by `secs_per_1k_chars` per 1,000 chars sent, like a real prefill."""
    def __init__(self, clock, secs_per_1k_chars=0.0, usage_tokens_per_char=1 / 3.4, fail=None, ctx=None):
        self.clock, self.k, self.tpc, self.fail, self.ctx, self.pings = clock, secs_per_1k_chars, usage_tokens_per_char, fail, ctx, []

    def ping(self, text, *, timeout):
        self.pings.append((len(text), timeout))
        if self.fail:
            raise ReviewUnavailable(self.fail)
        self.clock.t += self.k * len(text) / 1000
        return {"prompt_tokens": int(len(text) * self.tpc), "completion_tokens": 1} if self.tpc else None

    def context_length(self):
        return self.ctx


def _cfg(tmp_path, **rv):
    c = dataclasses.replace(Config(), db_path=tmp_path / "db.sqlite")
    return dataclasses.replace(c, reviewer=dataclasses.replace(c.reviewer, **rv))


def _guard(tmp_path, backend=None, clock=None, **rv):
    cfg = _cfg(tmp_path, **rv)
    conn = store.connect(cfg); store.init_schema(conn)
    clock = clock or Clock()
    said = []
    return g.ReviewerGuard(cfg, backend or Backend(clock), conn, clock=clock, memory=None, out=said.append), said


def test_cold_start_cap_until_measured(tmp_path):
    gd, _ = _guard(tmp_path)
    assert gd.input_cap_chars() == 40_000


def test_qwen_replay_cap_fits_the_timeout(tmp_path):
    # Last night: ~85 tok/s, 300 s timeout, 3.4 chars/token -> 85*300*0.6*3.4 ≈ 52k chars.
    gd, _ = _guard(tmp_path)
    gd.tok_s = 85.0
    assert 51_000 <= gd.input_cap_chars() <= 53_000
    assert "85 tok/s" in gd.cap_explain()


def test_fast_endpoint_is_limited_only_by_max_input_chars(tmp_path):
    gd, _ = _guard(tmp_path)
    gd.tok_s = 5000.0
    assert gd.input_cap_chars() == 200_000


def test_context_window_caps_the_input(tmp_path):
    clock = Clock()
    gd, _ = _guard(tmp_path, Backend(clock, secs_per_1k_chars=0.001, ctx=32_768), clock)
    gd.begin_batch()
    assert gd.input_cap_chars() < 32_768 * 3.4


def test_anthropic_skips_the_budget(tmp_path):
    gd, _ = _guard(tmp_path, provider="anthropic")
    assert gd.input_cap_chars() == 200_000


def test_calibration_probes_first_then_measures_without_package_content(tmp_path):
    clock = Clock()
    be = Backend(clock, secs_per_1k_chars=1.0)        # ~3.4 chars/token -> ~294 tok/s
    gd, said = _guard(tmp_path, be, clock)
    gd.begin_batch()
    assert [n for n, _ in be.pings] == [len(g.PROBE_TEXT), len(g.CALIBRATION_TEXT)]
    assert 250 < gd.tok_s < 350
    assert any("tokens/s" in s for s in said)
    # stored: a new guard on the same DB starts measured, with no calibration request
    be2 = Backend(clock)
    gd2 = g.ReviewerGuard(gd.cfg, be2, gd.conn, clock=clock, memory=None, out=said.append)
    gd2.begin_batch()
    assert be2.pings == [] and gd2.tok_s == gd.tok_s


def test_failed_calibration_keeps_cold_start_cap_and_retries_next_batch(tmp_path):
    clock = Clock()
    be = Backend(clock, fail="timed out")
    gd, _ = _guard(tmp_path, be, clock)
    gd.begin_batch()
    assert gd.tok_s is None and gd.input_cap_chars() == 40_000
    be.fail, be.k = None, 1.0
    gd2 = g.ReviewerGuard(gd.cfg, be, gd.conn, clock=clock, memory=None, out=lambda m: None)
    gd2.begin_batch()
    assert gd2.tok_s is not None


def test_rate_falls_back_to_chars_when_usage_missing(tmp_path):
    gd, _ = _guard(tmp_path)
    gd.record_success(None, secs=10.0, input_chars=34_000)   # ≈10k tokens / 10 s
    assert 950 < gd.tok_s < 1050


def test_small_requests_do_not_count_as_speed_samples(tmp_path):
    gd, _ = _guard(tmp_path)
    gd.record_success({"prompt_tokens": 500, "completion_tokens": 200}, secs=30.0, input_chars=1_700)
    assert gd.tok_s is None


def test_timeout_opens_breaker_until_a_probe_succeeds(tmp_path):
    clock = Clock()
    be = Backend(clock)
    gd, said = _guard(tmp_path, be, clock)
    gd.tok_s = 100.0
    assert gd.admit() is None
    gd.record_timeout()
    assert gd.admit() == "breaker open after timeout"
    assert any("timed out" in s for s in said)
    # next batch: a fresh guard from the DB is still open, probes, and closes
    gd2 = g.ReviewerGuard(gd.cfg, be, gd.conn, clock=clock, memory=None, out=said.append)
    assert gd2.admit() == "breaker open after timeout"
    gd2.begin_batch()
    assert gd2.admit() is None and be.pings[-1][0] == len(g.PROBE_TEXT)


def test_failed_probe_keeps_breaker_open_and_says_why(tmp_path):
    clock = Clock()
    be = Backend(clock, fail="reviewer endpoint returned HTTP 404: check the model name")
    gd, said = _guard(tmp_path, be, clock)
    gd.tok_s = 100.0
    gd.record_timeout()
    gd.begin_batch()
    assert gd.admit() == "breaker open after timeout"
    assert any("HTTP 404" in s for s in said)


def test_status_and_describe(tmp_path):
    gd, _ = _guard(tmp_path)
    gd.tok_s = 85.0
    st = gd.status()
    assert st["state"] == "closed" and st["tok_s"] == 85.0 and st["host_memory"] is None
    assert "85 tok/s" in g.describe(st) and "input cap" in g.describe(st)


def _u(tokens):
    return {"prompt_tokens": tokens, "completion_tokens": 100}


def _pps(rate, n=10_000):
    """A llama.cpp response: the server timed its own prefill of n tokens at `rate` tok/s."""
    return {"prompt_tokens": n, "completion_tokens": 100, "prompt_per_second": rate, "prompt_n": n}


def test_single_slow_sample_does_not_trip_or_lower_baseline(tmp_path):
    gd, said = _guard(tmp_path)
    gd.tok_s = 100.0
    gd.record_success(_pps(20.0), secs=500.0, input_chars=34_000)     # 20 tok/s: e.g. llama-swap cold load
    assert gd.admit() is None and gd.tok_s == 100.0
    gd.record_success(_pps(100.0), secs=100.0, input_chars=34_000)     # back to normal resets the streak
    gd.record_success(_pps(20.0), secs=500.0, input_chars=34_000)
    assert gd.admit() is None


def test_two_consecutive_slow_reviews_pause_with_a_warning(tmp_path):
    clock = Clock()
    be = Backend(clock)
    gd, said = _guard(tmp_path, be, clock)
    gd.tok_s = 100.0
    gd.record_success(_pps(20.0), secs=500.0, input_chars=34_000)
    gd.record_success(_pps(20.0), secs=500.0, input_chars=34_000)
    assert gd.admit() == "degraded" and gd.tok_s == 100.0
    assert any("20% of its measured speed" in s for s in said)
    gd.begin_batch()                                   # still inside the pause: no probe
    assert be.pings == []
    clock.t += 901
    gd.begin_batch()
    assert gd.admit() is None and len(be.pings) == 1


def test_degraded_also_posts_the_webhook(tmp_path, monkeypatch):
    sent = []
    monkeypatch.setattr(g.notifier, "post_webhook", lambda cfg, text: sent.append(text) or True)
    gd, _ = _guard(tmp_path)
    gd.tok_s = 100.0
    gd.record_success(_pps(20.0), secs=500.0, input_chars=34_000)
    assert sent == []
    gd.record_success(_pps(20.0), secs=500.0, input_chars=34_000)
    assert len(sent) == 1 and "measured speed" in sent[0]


class _Mem:
    def __init__(self, why):
        self.why = why

    def pressure(self):
        return self.why


def test_host_memory_pressure_defers_reviews(tmp_path):
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn)
    mem = _Mem("swap 83% used")
    gd = g.ReviewerGuard(cfg, Backend(Clock()), conn, clock=Clock(), memory=mem, out=lambda m: None)
    assert gd.admit() == "host memory: swap 83% used"
    mem.why = None
    assert gd.admit() is None


def test_small_llamacpp_prefill_is_not_a_speed_sample(tmp_path):
    # Short reviews share the cached system prompt: the server times only a few hundred tokens, and that
    # rate is dominated by overhead. Two of them must not pause a healthy 7.9k tok/s endpoint.
    gd, said = _guard(tmp_path)
    gd.tok_s = 7867.0
    for _ in range(2):
        gd.record_success(_pps(1500.0, n=1_200), secs=1.0, input_chars=4_000)
    assert gd.admit() is None and gd.tok_s == 7867.0 and said == []


def test_cached_prompt_tokens_do_not_inflate_the_speed(tmp_path):
    gd, _ = _guard(tmp_path)
    gd.record_success({"prompt_tokens": 12_000, "completion_tokens": 100, "prompt_per_second": 900.0,
                       "prompt_n": 300}, secs=0.5, input_chars=40_000)
    assert gd.tok_s is None


def test_slowdown_is_judged_only_on_server_timed_prefill(tmp_path):
    # Without llama.cpp timings, elapsed time includes output generation (a long reasoning answer) and
    # model loading, so a slow wall-clock sample is not evidence the server is degrading.
    gd, said = _guard(tmp_path)
    gd.tok_s = 100.0
    gd.record_success(_u(10_000), secs=500.0, input_chars=34_000)
    gd.record_success(_u(10_000), secs=500.0, input_chars=34_000)
    assert gd.admit() is None and said == [] and gd.tok_s == 100.0


def test_hosted_api_never_trips_the_slowdown_detector(tmp_path):
    gd, said = _guard(tmp_path, provider="anthropic")
    gd.tok_s = 100.0
    gd.record_success(_pps(20.0), secs=500.0, input_chars=34_000)
    gd.record_success(_pps(20.0), secs=500.0, input_chars=34_000)
    assert gd.admit() is None and said == []


def test_breaker_opened_by_another_process_is_honoured(tmp_path):
    clock = Clock()
    gd, _ = _guard(tmp_path, clock=clock)
    gd.tok_s = 100.0
    other = g.ReviewerGuard(gd.cfg, gd.backend, gd.conn, clock=clock, memory=None, out=lambda m: None)
    assert other.admit() is None
    gd.record_timeout()                                # the watch loop's guard opens the breaker
    assert other.admit() == "breaker open after timeout"


def test_a_success_elsewhere_does_not_close_an_open_breaker(tmp_path):
    clock = Clock()
    gd, _ = _guard(tmp_path, clock=clock)
    gd.tok_s = 100.0
    other = g.ReviewerGuard(gd.cfg, gd.backend, gd.conn, clock=clock, memory=None, out=lambda m: None)
    assert other.admit() is None                       # review-pending sends a review...
    gd.record_timeout()                                # ...while the watch loop's review times out
    other.record_success(_pps(100.0), secs=100.0, input_chars=34_000)
    assert store.get_reviewer_stats(gd.conn, gd.endpoint, gd.model)["state"] == "open"


def test_cap_explain_names_the_binding_limit(tmp_path):
    gd, _ = _guard(tmp_path)
    gd.tok_s = 7867.0
    assert "max_input_chars" in gd.cap_explain() and "tok/s" not in gd.cap_explain()
    gd.tok_s = None
    assert "until this endpoint's speed is measured" in gd.cap_explain()
    gd.tok_s, gd.ctx_tokens = 7867.0, 8_192
    assert "context window" in gd.cap_explain()


def test_default_probe_timeout_covers_a_llama_swap_cold_load():
    # Live: llama-swap loading Gemma 4 12B from cold took longer than 60 s, failing calibration.
    assert Config().reviewer.probe_timeout == 180.0


def test_small_context_window_still_leaves_room_for_input(tmp_path):
    # Final review: reserving the full max_output_tokens (32000) left a 32k-context endpoint a cap of 0.
    clock = Clock()
    gd, said = _guard(tmp_path, Backend(clock, secs_per_1k_chars=0.001, ctx=32_768), clock)
    gd.begin_batch()
    assert gd.input_cap_chars() > 40_000


def test_context_with_no_room_warns_once(tmp_path):
    clock = Clock()
    gd, said = _guard(tmp_path, Backend(clock, secs_per_1k_chars=0.001, ctx=1_000), clock)
    gd.begin_batch()
    assert gd.input_cap_chars() == 0 and gd.input_cap_chars() == 0
    assert len([s for s in said if "context window" in s]) == 1
