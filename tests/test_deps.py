import json
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


# ---- PR E: dependency context ----
def _dep_meta(*, days_ago=2, releases=1, roles=("mallory",), email=None, urls=None, org=None, home=None):
    first = (_fixed_now() - timedelta(days=days_ago))
    rel = {f"0.{i}": [{"upload_time_iso_8601": (first + timedelta(hours=i)).isoformat()}] for i in range(releases)}
    own = {"roles": [{"role": "Owner", "user": u} for u in roles]}
    if org:
        own["organization"] = org
    return {"info": {"author_email": email, "maintainer_email": None, "project_urls": urls or {}, "home_page": home},
            "ownership": own, "releases": rel}


_OWN = {"roles": {"acmedev"}, "emails": {"dev@example.org"}, "orgs": {("github.com", "acmedev")}}


def _screen(names, metas, own=_OWN, corpus=frozenset({"comtypes", "requests", "httpx"}), **kw):
    calls = []
    def fetch(name):
        calls.append(name)
        return metas.get(name, {})
    return deps.screen_added_deps(set(names), set(corpus), fetch_json=fetch, now=_fixed_now(), own=own, **kw), calls


def test_a_same_owner_candidate_is_not_a_typosquat_but_can_be_brand_new():
    # compyps shape: the scanned package's own owner, first uploaded minutes ago, 1 release
    out, _ = _screen({"compyps"}, {"compyps": _dep_meta(days_ago=0, roles=("acmedev",))})
    assert out == [{"name": "compyps", "reason": "brand-new", "same_owner": True}]


def test_an_old_many_release_candidate_is_cleared():
    # vpype shape: 21 releases since 2020-11-29, a different owner
    meta = _dep_meta(days_ago=(_fixed_now() - datetime(2020, 11, 29, tzinfo=timezone.utc)).days, releases=21)
    out, _ = _screen({"vpype"}, {"vpype": meta}, corpus={"jpype1"})
    assert out == []


def test_old_but_thin_stays_a_typosquat():
    out, calls = _screen({"reqursts"}, {"reqursts": _dep_meta(days_ago=730, releases=1)})
    assert out[0]["reason"] == "typosquat" and out[0]["releases"] == 1 and out[0]["owner"] == "different"
    assert calls == ["reqursts"]                        # no candidate email: the target is not fetched


def test_an_author_declared_match_annotates_and_never_clears():
    meta = _dep_meta(days_ago=730, releases=1, email="Dev <Dev@Example.org>",
                     urls={"Source": "https://GitHub.com/AcmeDev/compyps"})
    out, _ = _screen({"reqursts"}, {"reqursts": meta})
    assert out[0]["reason"] == "typosquat" and out[0]["same_author_email"] is True and out[0]["same_org"] is True


def test_an_author_declared_match_on_a_young_candidate_is_a_typosquat_not_brand_new():
    meta = _dep_meta(days_ago=0, releases=1, email="dev@example.org",
                     urls={"Source": "https://github.com/acmedev/x"})
    out, _ = _screen({"reqursts"}, {"reqursts": meta})
    assert [f["reason"] for f in out] == ["typosquat"]


def test_a_404_candidate_is_nonexistent_with_its_target():
    out, _ = _screen({"reqursts"}, {"reqursts": None})
    assert out == [{"name": "reqursts", "reason": "nonexistent", "target": "requests"}]


def test_a_transient_lookup_keeps_the_plain_typosquat():
    out, _ = _screen({"reqursts"}, {})                  # fetch_json returned {}
    assert out == [{"name": "reqursts", "reason": "typosquat", "target": "requests"}]


def test_the_cap_is_shared_and_leaves_the_plain_typosquat():
    out, calls = _screen({"reqursts", "reqwests"}, {"reqursts": _dep_meta(), "reqwests": _dep_meta()}, cap=1)
    assert len(calls) == 1
    assert {"name": "reqwests", "reason": "typosquat", "target": "requests"} in out


def test_missing_roles_make_the_owner_unknown_and_never_clear():
    out, _ = _screen({"reqursts"}, {"reqursts": _dep_meta(roles=())})
    assert out[0]["reason"] == "typosquat" and out[0]["owner"] == "unknown"
    out, _ = _screen({"reqursts"}, {"reqursts": _dep_meta(roles=("acmedev",))},
                     own={"roles": set(), "emails": set(), "orgs": set()})
    assert out[0]["reason"] == "typosquat" and out[0]["owner"] == "unknown"


def test_a1_the_target_shares_an_author_and_the_candidate_has_a_pypi_org():
    # httpx2 shape: the same author on both, a different owner, organisation pydantic, 18 releases in ~4.5 months
    cand = _dep_meta(days_ago=139, releases=18, roles=("successor-dev",), org="pydantic",
                     email="Author <author@example.org>")
    target = _dep_meta(days_ago=3000, releases=60, roles=("orig-dev-1", "orig-dev-2"),
                       email="Author <author@example.org>")
    out, calls = _screen({"httpx2"}, {"httpx2": cand, "httpx": target})
    assert calls == ["httpx2", "httpx"]
    f = out[0]
    assert (f["reason"], f["same_author_as_target"], f["pypi_org"]) == ("typosquat", True, "pydantic")
    assert f["first_upload"] == (_fixed_now() - timedelta(days=139)).date().isoformat() and f["releases"] == 18


def test_a1_the_target_lookup_respects_the_cap():
    cand = _dep_meta(email="author@example.org")
    out, calls = _screen({"httpx2"}, {"httpx2": cand, "httpx": _dep_meta(email="author@example.org")}, cap=1)
    assert calls == ["httpx2"] and out[0]["same_author_as_target"] is False


def test_identity_parses_emails_and_code_host_orgs():
    ident = deps.identity({"info": {"author_email": "A <X@Y.org>, b@z.org", "maintainer_email": None,
                                    "project_urls": {"Source": "https://GitHub.com/Org/Repo",
                                                     "Docs": "https://example.org/Org"},
                                    "home_page": "https://gitlab.com/Team/x"},
                           "ownership": {"roles": [{"role": "Owner", "user": "Alice"}]}})
    assert ident == {"roles": {"alice"}, "emails": {"x@y.org", "b@z.org"},
                     "orgs": {("github.com", "org"), ("gitlab.com", "team")}}


def test_identity_tolerates_hostile_json():
    # Review Focus 1
    for meta in ({"ownership": {"roles": "x"}}, {"ownership": {"roles": [{"role": "Owner"}, "u", 3]}},
                 {"info": {"project_urls": "https://github.com/a/b", "author_email": 5}}, {"info": None},
                 {"ownership": None}, {}):
        assert deps.identity(meta) == {"roles": set(), "emails": set(), "orgs": set()}


def test_a_hostile_candidate_json_never_crashes_or_clears():
    # Review Focus 1
    meta = {"info": "x", "ownership": {"roles": [{"user": 7}]}, "releases": {"1.0": "not a list", "2.0": None}}
    out, _ = _screen({"reqursts"}, {"reqursts": meta})
    assert out[0]["reason"] == "typosquat" and out[0]["releases"] == 0 and out[0]["first_upload"] is None
    out, _ = _screen({"reqursts"}, {"reqursts": [1, 2]})               # a non-dict JSON document
    assert out == [{"name": "reqursts", "reason": "typosquat", "target": "requests"}]


def test_findings_never_carry_an_email():
    # Review Focus 3
    meta = _dep_meta(days_ago=730, releases=1, email="dev@example.org")
    out, _ = _screen({"reqursts", "compyps"}, {"reqursts": meta, "compyps": _dep_meta(roles=("acmedev",))})
    assert "@" not in json.dumps(out)
