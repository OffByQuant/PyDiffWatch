"""The sandboxed side of pydiffwatch.sandbox (parse-sandbox spec §3.2). Reads one request on stdin, writes one JSON
line on stdout, and exits.

A scan request is a JSON line followed by the raw sdists; the reply is the diff and the rules that fired, or the
error. A probe request asks the worker to try what the sandbox must stop, and reports what happened. It never
fetches a URL and never runs package content: its one process launch is the probe's /usr/bin/true, which the
sandbox must deny. Every path it touches arrives absolute from the parent: inside the sandbox the home directory
cannot be looked up."""
import errno
import hashlib
import json
import os
import socket
import subprocess
import sys


def _attempt(fn) -> str:
    try:
        fn()
    except OSError:
        return "blocked"
    return "open"


def _net() -> str:
    """Only the errors a network deny gives count as blocked (Seatbelt: EPERM; PrivateNetwork: ENETUNREACH). A
    timeout or a refused connection means the packet left the worker, so a firewall or an unreachable server
    cannot mask an open network (Ruling R14)."""
    try:
        socket.create_connection(("1.1.1.1", 53), timeout=3).close()
    except PermissionError:
        return "blocked"
    except OSError as e:
        return "blocked" if e.errno in (errno.EPERM, errno.ENETUNREACH, errno.EACCES) else "open"
    return "open"


def _probe(head) -> dict:
    def write():
        with open(head["write_target"], "w") as f:
            f.write("x")

    def read_home():
        with open(head["home_file"], "rb") as f:
            f.read(1)

    def read_db():
        with open(head["db_file"], "rb") as f:
            f.read(1)

    def run_program():
        subprocess.run(["/usr/bin/true"], capture_output=True, timeout=5)

    seen = {hashlib.sha256(v.encode("utf-8", "surrogateescape")).hexdigest() for v in os.environ.values()}
    return {"network": _net(), "write": _attempt(write),
            "home_read": _attempt(read_home) if head.get("home_file") else "unknown",
            "db_read": _attempt(read_db), "exec": _attempt(run_program), "services": _services(),
            "env": "leaked" if seen & set(head["env_hashes"]) else "clean"}


def _services() -> str:
    """macOS: can the worker reach LaunchServices, which opens URLs and apps outside the sandbox?"""
    if sys.platform != "darwin":
        return "n/a"
    import ctypes
    import ctypes.util
    libc = ctypes.CDLL(ctypes.util.find_library("System"))
    port = ctypes.c_uint32(0)
    kr = libc.bootstrap_look_up(ctypes.c_uint32.in_dll(libc, "bootstrap_port"),
                                b"com.apple.coreservices.launchservicesd", ctypes.byref(port))
    return "open" if kr == 0 else "blocked"


def main() -> None:
    stdin = sys.stdin.buffer
    head = json.loads(stdin.readline())
    sys.path[:0] = [p for p in head["sys_path"] if p not in sys.path]
    # The scan code is imported before anything is answered, the probe included (Ruling R3): an install whose
    # dependencies the sandbox cannot read then fails the probe, so choose() falls back or refuses, instead of
    # holding while every scan fails.
    from . import fetcher, sandbox
    if head.get("probe"):
        out = json.dumps(_probe(head), sort_keys=True).encode()
    else:
        try:
            out = sandbox._encode_output(*sandbox.compute(*sandbox._decode_input(head, stdin)))
        except fetcher.RefusedToExtract as e:
            out = json.dumps({"error": str(e), "error_type": "RefusedToExtract"}, sort_keys=True).encode()
        except Exception as e:              # the parent turns this into a retryable scan failure
            out = json.dumps({"error": f"{type(e).__name__}: {e}"}, sort_keys=True).encode()
    sys.stdout.buffer.write(out)
    sys.stdout.flush()


if __name__ == "__main__":
    main()
