"""The sandboxed side of pydiffwatch.sandbox (parse-sandbox spec §3.2). Reads one request on stdin, writes one JSON
line on stdout, and exits. A scan request is a JSON line followed by the raw sdists; the reply is the diff and the
rules that fired, or the error. It never fetches a URL and never runs package content. Every path it touches
arrives absolute from the parent: inside the sandbox the home directory cannot be looked up."""
import json
import sys


def main() -> None:
    stdin = sys.stdin.buffer
    head = json.loads(stdin.readline())
    sys.path[:0] = [p for p in head["sys_path"] if p not in sys.path]
    # The scan code is imported before anything is answered (Ruling R3): an install whose dependencies the sandbox
    # cannot read fails as a whole, not one release at a time.
    from . import fetcher, sandbox
    try:
        out = sandbox._encode_output(*sandbox.compute(*sandbox._decode_input(head, stdin)))
    except fetcher.RefusedToExtract as e:
        out = json.dumps({"error": str(e), "error_type": "RefusedToExtract"}, sort_keys=True).encode()
    except Exception as e:                  # the parent turns this into a retryable scan failure
        out = json.dumps({"error": f"{type(e).__name__}: {e}"}, sort_keys=True).encode()
    sys.stdout.buffer.write(out)
    sys.stdout.flush()


if __name__ == "__main__":
    main()
