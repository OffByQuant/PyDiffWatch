"""Rebuild pydiffwatch/data/top_pypi_orgs.txt: the PyPI organisation of each top-PyPI package.

Run by hand, in the same run and PR as a top_pypi_names.txt refresh:

    python3 tools/build_top_orgs.py

It GETs https://pypi.org/pypi/<name>/json for every name in top_pypi_names.txt (about 5,000 requests, a few GB,
roughly 15-30 minutes) and keeps only `ownership.organization`. It writes nothing and exits non-zero when more
than 5% of names fail or fewer than 20 organisations are found (a schema change that drops `ownership`).
"""
import datetime
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from pydiffwatch import deps, fetcher              # noqa: E402
from pydiffwatch.config import Config               # noqa: E402

MAX_FAIL_RATE = 0.05
MIN_ORGS = 20


def _org(name: str, cfg: Config):
    url = f"{cfg.pypi_base}/pypi/{urllib.parse.quote(name, safe='')}/json"
    req = urllib.request.Request(url, headers={"User-Agent": "diffwatch/0.1", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=cfg.fetch_timeout_s) as r:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        return deps.org_of(json.loads(fetcher.read_body(r, cfg, cfg.max_metadata_bytes, cfg.packument_deadline_s)))


def main() -> int:
    cfg = Config()
    names = sorted(deps.load_corpus())
    with open(deps._CORPUS_PATH, encoding="utf-8") as f:
        m = re.search(r"fetched (\d{4}-\d{2}-\d{2})", f.read())
    corpus_date = m.group(1) if m else "unknown"

    def one(name):
        try:
            return name, _org(name, cfg), None
        except Exception as e:
            return name, None, e
    with ThreadPoolExecutor(max_workers=4) as ex:
        results = list(ex.map(one, names))
    failed = [n for n, _, e in results if e is not None]
    rows = sorted({(org, name) for name, org, _ in results if org})
    orgs = {o for o, _ in rows}
    popular = {o for o in orgs if sum(1 for oo, _ in rows if oo == o) >= 2}
    print(f"names {len(names)}, failed {len(failed)}, packages with an organisation {len(rows)}, "
          f"organisations {len(orgs)}, owning 2+ packages {len(popular)}")
    if len(failed) > MAX_FAIL_RATE * len(names):
        print(f"too many failures ({len(failed)}); not writing. First: {failed[:10]}", file=sys.stderr)
        return 1
    if len(orgs) < MIN_ORGS:
        print(f"only {len(orgs)} organisations; PyPI JSON may have changed shape. Not writing.", file=sys.stderr)
        return 1
    today = datetime.date.today().isoformat()
    with open(deps._ORGS_PATH, "w", encoding="utf-8") as f:
        f.write(f"# PyPI organisation of each top-PyPI package that has one (ownership.organization in\n"
                f"# /pypi/<name>/json), fetched {today} by tools/build_top_orgs.py from top_pypi_names.txt\n"
                f"# (itself fetched {corpus_date}). organisation<TAB>package, PEP 503-normalized. VENDORED (not\n"
                f"# runtime-fetched). Refresh manually, in the same run and PR as top_pypi_names.txt.\n")
        for org, name in rows:
            f.write(f"{org}\t{name}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
