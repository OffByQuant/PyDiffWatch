import argparse
from . import egress
from .config import Config, load_config
from .orchestrator import (run_once, seed_now, list_pending, adjudicate, get_evidence,
                           backfill_evidence, export_dashboard, watch)


def _cfg(args):
    return load_config(args.config) if args.config else Config()


def _reach(host):
    """Human note about who can reach a given bind address."""
    if host in ("127.0.0.1", "localhost"):
        return "localhost only"
    return "exposed to the local network — anyone who can reach this host"


def _file_server(directory, port, host="127.0.0.1"):
    """A read-only static file server (no control endpoints). Binds 127.0.0.1 by
    default; pass host="0.0.0.0" to expose it to the local network."""
    import functools
    from http.server import SimpleHTTPRequestHandler, HTTPServer
    handler = functools.partial(SimpleHTTPRequestHandler, directory=str(directory))
    return HTTPServer((host, port), handler)


def main():
    p = argparse.ArgumentParser(prog="pydiffwatch")
    p.add_argument("-c", "--config", default=None,
                   help="path to a pydiffwatch.toml config file (see examples/); defaults to built-ins")
    sub = p.add_subparsers(dest="cmd", required=True)
    runp = sub.add_parser("run", help="process new releases since the cursor (one tick)")
    runp.add_argument("--backfill", action="store_true",
                      help="process from the cursor as-is (PyPI genesis on a fresh DB) instead of "
                           "seeding a fresh cursor to now")
    sub.add_parser("seed-now",
                   help="set the cursor to PyPI's current serial and exit (start monitoring from now)")
    sub.add_parser("pending",
                   help="list suspicious verdicts awaiting adjudication, each with its diff")
    adjp = sub.add_parser("adjudicate", help="record your verdict on a queued suspicious release")
    adjp.add_argument("release_id", type=int)
    adjp.add_argument("label", choices=["benign", "malicious", "suspicious"])
    adjp.add_argument("--note", default="")
    evp = sub.add_parser("evidence", help="print the stored flagged payload code for a release")
    evp.add_argument("release_id", type=int)
    capp = sub.add_parser("capture-evidence",
                          help="backfill stored payload code for flagged releases captured before "
                               "evidence existed (re-fetches from PyPI while still available)")
    capp.add_argument("--release-id", type=int, default=None,
                      help="capture just this release id (default: all reportable rows missing evidence)")
    capp.add_argument("--all", action="store_true",
                      help="widen from the reportable set (malicious/suspicious verdicts + non-benign "
                           "alerts) to EVERY release with a fired rule (far more PyPI re-fetches)")
    dshp = sub.add_parser("dashboard",
                          help="render persisted verdicts to a self-contained HTML page with PyPI "
                               "links and one-click 'Report malware' actions for flagged packages")
    dshp.add_argument("--out", default=None,
                      help="output HTML path (default: <db dir>/dashboard.html)")
    dshp.add_argument("--serve", action="store_true",
                      help="serve the dashboard on 127.0.0.1 (localhost only) until Ctrl-C")
    dshp.add_argument("--port", type=int, default=8787, help="port for --serve (default: 8787)")
    dshp.add_argument("--host", default="127.0.0.1",
                      help="bind address for --serve (default: 127.0.0.1, localhost only; "
                           "use 0.0.0.0 to expose it to the local network)")
    wp = sub.add_parser("watch",
                        help="daemon loop: scan for new releases on an interval, refresh the "
                             "dashboard each tick, and (with --serve) serve it on localhost")
    wp.add_argument("--interval", type=int, default=300, help="seconds between scans (default: 300)")
    wp.add_argument("--out", default=None, help="dashboard HTML path (default: <db dir>/dashboard.html)")
    wp.add_argument("--serve", action="store_true",
                    help="also serve the dashboard on 127.0.0.1 (localhost only) while watching")
    wp.add_argument("--port", type=int, default=8787, help="port for --serve (default: 8787)")
    wp.add_argument("--host", default="127.0.0.1",
                    help="bind address for --serve (default: 127.0.0.1, localhost only; "
                         "use 0.0.0.0 to expose it to the local network)")
    args = p.parse_args()
    cfg = _cfg(args)
    # xmlrpc.client is defused at import in ingest.py (covers library importers too). The egress guard
    # mutates global socket state, so it stays a CLI-entry concern (see egress.py docstring).
    egress.install_guard(cfg)   # default-deny host allowlist for the whole process (see egress.py)
    if args.cmd == "run":
        n = run_once(cfg, seed_if_fresh=not args.backfill)
        print(f"[pydiffwatch] processed {n} releases")
    elif args.cmd == "seed-now":
        s = seed_now(cfg)
        print(f"[pydiffwatch] cursor seeded to serial {s}" if s is not None
              else "[pydiffwatch] could not reach PyPI to read the current serial")
    elif args.cmd == "pending":
        items = list_pending(cfg)
        if not items:
            print("[pydiffwatch] no suspicious verdicts awaiting adjudication"); return
        print(f"[pydiffwatch] {len(items)} suspicious verdict(s) awaiting adjudication:\n")
        for it in items:
            print(f"=== release_id={it['release_id']}  {it['package']}=={it['version']}  "
                  f"(model: {it['classification']} conf={it['confidence']} attack={it['attack_type']}) ===")
            print(f"  model reason: {it['reasoning']}")
            print(f"  cited_hunk: {it['cited_hunk']}")
            if it["diff_text"] is not None:
                label = "stored payload evidence" if it["evidence_stored"] else "diff under review (re-fetched)"
                print(f"  --- {label} ---")
                print(it["diff_text"])
            else:
                print(f"  (diff unavailable: {it['fetch_error']})")
            print()
    elif args.cmd == "evidence":
        ev = get_evidence(cfg, args.release_id)
        if ev is None:
            print(f"[pydiffwatch] no stored evidence for release_id {args.release_id} "
                  "(unknown id, or detected before evidence capture — try 'capture-evidence')")
        else:
            print(ev)
    elif args.cmd == "capture-evidence":
        res = backfill_evidence(cfg, release_id=args.release_id, all_flagged=args.all)
        if not res:
            print("[pydiffwatch] no flagged releases missing evidence"); return
        ok = sum(1 for r in res if r["captured"])
        print(f"[pydiffwatch] captured {ok}/{len(res)} flagged release(s):")
        for r in res:
            status = "captured" if r["captured"] else f"FAILED ({r['error']})"
            print(f"  {r['package']}=={r['version']}: {status}")
    elif args.cmd == "dashboard":
        out = export_dashboard(cfg, out_path=args.out)
        print(f"[pydiffwatch] dashboard written to {out}")
        if args.serve:
            httpd = _file_server(out.parent, args.port, args.host)
            print(f"[pydiffwatch] serving on http://{args.host}:{args.port}/{out.name} "
                  f"({_reach(args.host)}) — Ctrl-C to stop")
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                print("\n[pydiffwatch] stopped")
            finally:
                httpd.server_close()
    elif args.cmd == "watch":
        out = export_dashboard(cfg, out_path=args.out)  # initial snapshot for the server
        httpd = None
        if args.serve:
            import threading
            httpd = _file_server(out.parent, args.port, args.host)
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            print(f"[pydiffwatch] serving http://{args.host}:{args.port}/{out.name} ({_reach(args.host)})")
        print(f"[pydiffwatch] watching — scanning every {args.interval}s, Ctrl-C to stop")
        n = watch(cfg, interval=args.interval, out_path=args.out)
        if httpd:
            httpd.server_close()
        print(f"\n[pydiffwatch] stopped after {n} scan(s)")
    elif args.cmd == "adjudicate":
        res = adjudicate(cfg, args.release_id, args.label, args.note)
        if res is None:
            print(f"[pydiffwatch] release_id {args.release_id} not found")
        else:
            print(f"[pydiffwatch] {res['package']}=={res['version']} adjudicated {res['label']}"
                  + ("  (alert emitted)" if res["alerted"] else "  (no alert)"))


if __name__ == "__main__":
    main()
