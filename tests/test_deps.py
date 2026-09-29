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


# ---- popular PyPI organisation clears a typosquat-close dep (spec 2026-09-29) ----
_ACME_CORPUS = frozenset({"acme-http", "acme-core", "acme-models"})
_ORGS = frozenset({"acme-org"})


def _org_screen(metas, names=("acme-http2",), **kw):
    return _screen(set(names), metas, corpus=_ACME_CORPUS, orgs=kw.pop("orgs", _ORGS), **kw)


def test_org_of_normalizes_and_rejects_non_strings():
    assert deps.org_of({"ownership": {"organization": "  Acme_Org "}}) == "acme-org"
    for meta in ({"ownership": {"organization": ""}}, {"ownership": {"organization": None}},
                 {"ownership": {"organization": 3}}, {"ownership": None}, {}, None, [1]):
        assert deps.org_of(meta) is None


def test_a_popular_org_dep_is_not_a_typosquat_and_its_target_is_not_fetched():
    cand = _dep_meta(days_ago=139, releases=18, roles=("successor-dev",), org="acme-org", email="a@example.org")
    out, calls = _org_screen({"acme-http2": cand, "acme-http": _dep_meta(email="a@example.org")})
    assert out == [] and calls == ["acme-http2"]


def test_a_young_popular_org_dep_is_brand_new_with_its_org():
    out, _ = _org_screen({"acme-http2": _dep_meta(days_ago=2, org="Acme_Org")})
    assert out == [{"name": "acme-http2", "reason": "brand-new", "pypi_org": "acme-org"}]


def test_same_owner_and_popular_org_carry_both():
    out, _ = _org_screen({"acme-http2": _dep_meta(days_ago=2, roles=("acmedev",), org="acme-org")})
    assert out == [{"name": "acme-http2", "reason": "brand-new", "same_owner": True, "pypi_org": "acme-org"}]


def test_an_org_outside_the_map_stays_a_typosquat_with_its_org():
    out, _ = _org_screen({"acme-http2": _dep_meta(days_ago=139, releases=18, org="other-org")})
    assert out[0]["reason"] == "typosquat" and out[0]["pypi_org"] == "other-org"


def test_a_missing_or_odd_org_stays_a_typosquat():
    for org in (None, "", "   "):
        meta = _dep_meta(days_ago=139, releases=18)
        meta["ownership"]["organization"] = org
        out, _ = _org_screen({"acme-http2": meta})
        assert out[0]["reason"] == "typosquat"


def test_a_young_popular_org_dep_that_is_not_typosquat_close_is_brand_new_with_its_org():
    out, _ = _org_screen({"zzqx-tool": _dep_meta(days_ago=2, org="acme-org")}, names=("zzqx-tool",))
    assert out == [{"name": "zzqx-tool", "reason": "brand-new", "pypi_org": "acme-org"}]


def test_a_transient_or_capped_lookup_ignores_the_org_map():
    out, _ = _org_screen({})                                               # fetch_json returned {}
    assert out == [{"name": "acme-http2", "reason": "typosquat", "target": "acme-http"}]
    out, _ = _org_screen({"acme-http2": _dep_meta(org="acme-org"), "acme-httpx": _dep_meta(org="acme-org")},
                         names=("acme-http2", "acme-httpx"), cap=1)
    assert {"name": "acme-httpx", "reason": "typosquat", "target": "acme-http"} in out


def test_without_orgs_the_org_is_only_annotated():
    meta = _dep_meta(days_ago=139, releases=18, org="acme-org")
    out, _ = _screen({"acme-http2"}, {"acme-http2": meta}, corpus=_ACME_CORPUS)
    assert out[0]["reason"] == "typosquat" and out[0]["pypi_org"] == "acme-org"


def test_load_popular_orgs_needs_two_packages(tmp_path):
    p = tmp_path / "orgs.txt"
    p.write_bytes(b"# header\r\n\r\nacme-org\tacme-core\r\nAcme_Org\tacme-models\r\nacme-org\tacme-core\r\n"
                  b"solo-org\tacme-http\r\nbroken-line\r\ndup-org\tacme-a\ndup-org\tacme-a\n")
    assert deps.load_popular_orgs(str(p)) == frozenset({"acme-org"})
    assert deps.load_popular_orgs(str(p), min_packages=1) == frozenset({"acme-org", "solo-org", "dup-org"})


def test_load_popular_orgs_missing_file_is_empty(tmp_path):
    assert deps.load_popular_orgs(str(tmp_path / "absent.txt")) == frozenset()


def test_load_popular_orgs_skips_lines_without_exactly_two_columns(tmp_path):
    p = tmp_path / "orgs.txt"
    p.write_text("solo-org\tacme-a\ta note\nsolo-org\tacme-a\n")
    assert deps.load_popular_orgs(str(p)) == frozenset()


def test_load_popular_orgs_unreadable_file_is_empty(tmp_path):
    p = tmp_path / "orgs.txt"
    p.write_bytes(b"acme-org\tacme-a\n\xff\xfe\x00bad\n")
    assert deps.load_popular_orgs(str(p)) == frozenset()


def test_the_vendored_org_map_is_populated_and_matches_the_names_corpus():
    import re
    assert len(deps.load_popular_orgs()) >= 20
    corpus = deps.load_corpus()
    with open(deps._ORGS_PATH, encoding="utf-8") as f:
        text = f.read()
    rows = [ln.split("\t") for ln in text.splitlines() if ln and not ln.startswith("#")]
    assert rows and all(len(r) == 2 and r[1] in corpus for r in rows)
    with open(deps._CORPUS_PATH, encoding="utf-8") as f:
        names_date = re.search(r"fetched (\d{4}-\d{2}-\d{2})", f.read()).group(1)
    assert f"(itself fetched {names_date})" in text     # rebuilt in the same refresh as top_pypi_names.txt
