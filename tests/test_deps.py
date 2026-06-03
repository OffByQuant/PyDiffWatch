from datetime import datetime, timezone, timedelta
from pydiffwatch import deps


# --- normalization + parsing (pure) ---

def test_normalize_name_pep503():
    assert deps.normalize_name("Flask_SQLAlchemy") == "flask-sqlalchemy"
    assert deps.normalize_name("zope.interface") == "zope-interface"
    assert deps.normalize_name("Django") == "django"
    assert deps.normalize_name("a--_.b") == "a-b"


def test_parse_requires_dist_strips_specifiers_extras_markers():
    lines = [
        "charset-normalizer (<4,>=2)",
        "idna<4,>=2.5",
        "PySocks (!=1.5.7,>=1.5.6) ; extra == 'socks'",
        "requests[security]>=2.0",
    ]
    assert deps.parse_requires_dist(lines) == {"charset-normalizer", "idna", "pysocks", "requests"}


# --- corpus ---

def test_load_corpus_normalized_and_skips_comments():
    corpus = deps.load_corpus()
    assert "requests" in corpus and "numpy" in corpus
    assert not any(c.startswith("#") for c in corpus)        # comment lines excluded
    assert all(c == deps.normalize_name(c) for c in list(corpus)[:50])  # already normalized


# --- edit distance + typosquat ---

def test_edit_distance():
    assert deps.edit_distance("requests", "requests") == 0
    assert deps.edit_distance("reqursts", "requests") == 1   # transposition-ish: one edit region
    assert deps.edit_distance("abc", "abcd") == 1


def test_nearest_corpus_flags_close_name_excludes_exact_and_short():
    corpus = {"requests", "urllib3", "numpy", "abcd"}
    assert deps.nearest_corpus("reqursts", corpus, max_dist=2) == "requests"   # 1 edit
    assert deps.nearest_corpus("requests", corpus, max_dist=2) is None         # exact = not a squat
    assert deps.nearest_corpus("zzzzzzzz", corpus, max_dist=2) is None         # far from everything
    assert deps.nearest_corpus("abce", corpus, max_dist=2) is None             # too short (<=4) -> guard


# --- the screening gate ---

def _fixed_now():
    return datetime(2026, 6, 2, tzinfo=timezone.utc)


def _json_with_earliest(days_ago):
    ts = (_fixed_now() - timedelta(days=days_ago)).isoformat()
    return {"releases": {"1.0": [{"upload_time_iso_8601": ts}]}}


def test_corpus_member_not_flagged_and_not_fetched():
    calls = []
    def fetch(name): calls.append(name); return _json_with_earliest(1)
    out = deps.screen_added_deps({"requests"}, {"requests"}, fetch_json=fetch, now=_fixed_now())
    assert out == [] and calls == []                         # whitelisted -> no flag, no network


def test_typosquat_flagged_without_fetch():
    calls = []
    def fetch(name): calls.append(name); return _json_with_earliest(1)
    out = deps.screen_added_deps({"reqursts"}, {"requests"}, fetch_json=fetch, now=_fixed_now())
    assert out == [{"name": "reqursts", "reason": "typosquat", "target": "requests"}]
    assert calls == []                                       # typosquat decided locally, no network


def test_nonexistent_dep_flagged():
    def fetch(name): return None                             # 404
    out = deps.screen_added_deps({"xj9-helper"}, {"requests"}, fetch_json=fetch, now=_fixed_now())
    assert out == [{"name": "xj9-helper", "reason": "nonexistent"}]


def test_brand_new_dep_flagged_mature_is_not():
    def fetch(name):
        return _json_with_earliest(2) if name == "freshpkg" else _json_with_earliest(900)
    out = deps.screen_added_deps({"freshpkg", "maturepkg"}, {"requests"},
                                 fetch_json=fetch, now=_fixed_now(), brandnew_days=30)
    assert {"name": "freshpkg", "reason": "brand-new"} in out
    assert all(f["name"] != "maturepkg" for f in out)        # 900 days old -> not flagged


def test_fetch_cap_records_overflow_without_fetching():
    calls = []
    def fetch(name): calls.append(name); return None
    added = {f"pkg{i}" for i in range(15)}
    out = deps.screen_added_deps(added, {"requests"}, fetch_json=fetch, now=_fixed_now(), cap=10)
    assert len(calls) == 10                                  # only cap deps fetched
    capped = [f for f in out if f["reason"] == "not-screened-cap"]
    assert len(capped) == 5                                  # the rest recorded, never silently dropped


def test_cache_prevents_refetch_across_calls():
    calls = []
    def fetch(name): calls.append(name); return None
    cache = {}
    deps.screen_added_deps({"xj9"}, {"requests"}, fetch_json=fetch, now=_fixed_now(), cache=cache)
    deps.screen_added_deps({"xj9"}, {"requests"}, fetch_json=fetch, now=_fixed_now(), cache=cache)
    assert calls == ["xj9"]                                  # second call served from cache
