"""Spec F §3.3: the chain gate. A malicious verdict stands only when the model quoted a chain the shown code
contains. Pure: it reads the verdict's quotes and `shown` (the lines the model was shown), never package bytes, and
never runs or fetches anything."""
import builtins, io, keyword, re, tokenize

SOURCE_KINDS = ("secret-read", "payload", "fetch", "none")
SINK_KINDS = ("send", "exec", "write-and-run", "none")
QUOTE_MAX = 2_000

_MODULE_SPAN = 50
_PREFIX = re.compile(r"^(?:[+-](?=\s|$)|L?\d+:)")
_AT_MARKER = re.compile(r"^@@[^@]*@@\s*")            # a sandwiched marker: strip it, keep any code after it (m8)
_IMPORT_LINE = re.compile(r"^\s*(?:import\s|from\s+\S+\s+import\b)")
_NOISE = {tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT, tokenize.ENDMARKER, tokenize.COMMENT}
_NOT_NAMES = set(keyword.kwlist) | set(getattr(keyword, "softkwlist", [])) | set(dir(builtins))
_FSTRING_START = getattr(tokenize, "FSTRING_START", None)
_FSTRING_MIDDLE = getattr(tokenize, "FSTRING_MIDDLE", None)
_FSTRING_END = getattr(tokenize, "FSTRING_END", None)


def _norm(s: str) -> str:
    return " ".join(s.split())


def clean(quote) -> list:
    """A quote as (raw, prefix-stripped) normalised line pairs: blank lines, `...`, `@@` position lines and copied
    file headings dropped (spec F §3.3 check 2); a `@@ ... @@` marker sandwiched in front of real code has just the
    marker stripped, not the whole line (fix m8). Both forms are tried, so a real `12: 'x'` line still matches."""
    out = []
    for ln in (quote if isinstance(quote, str) else "").split("\n"):
        s = ln.strip()
        if not s or s in ("...", "…") or s.startswith("--- file:"):
            continue
        if s.startswith("@@"):
            m = _AT_MARKER.match(s)
            if not m:
                continue
            s = s[m.end():].strip()
            if not s:
                continue
        out.append((_norm(s), _norm(_PREFIX.sub("", s, count=1))))
    return [pair for pair in out if pair[1]]


def cited(verdict) -> bool:
    """Check 1 (Present): both kinds declared and both quotes non-empty after cleaning."""
    return (getattr(verdict, "source_kind", None) not in (None, "none")
            and getattr(verdict, "sink_kind", None) not in (None, "none")
            and bool(clean(getattr(verdict, "chain_source", None)))
            and bool(clean(getattr(verdict, "chain_sink", None))))


def _tokens(text: str) -> list:
    """A shown line's tokens, isolated from the rest of its file: whatever tokenize produced before it hit an
    error (an incomplete multi-line call/string/binding reads on its own as unterminated, but the tokens up to
    that point are still real — fix R3 round 3: no lexical retry here; a string-tail line is instead handled by
    the caller passing in only the code portion of the line, via reviewer's "tails" (fix R3)."""
    out = []
    try:
        for t in tokenize.generate_tokens(io.StringIO(text.strip() + "\n").readline):
            out.append(t)
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass
    return [t for t in out if t.type not in _NOISE]


def _collapse_fstrings(toks: list) -> list:
    """Each FSTRING_START..FSTRING_END span collapsed to one synthetic STRING token (fix I3a): a line that is only
    an f-string reads as only a string for `_live`, on Python 3.12+ where f-strings tokenize into parts. `_names`
    does not use this — it still sees the real tokens, so names inside `{}` replacement fields still count."""
    if _FSTRING_START is None:
        return toks
    out, depth = [], 0
    for t in toks:
        if t.type == _FSTRING_START:
            if depth == 0:
                out.append(t._replace(type=tokenize.STRING))
            depth += 1
        elif t.type == _FSTRING_END:
            depth -= 1
        elif depth == 0:
            out.append(t)
    return out


def _live(text: str) -> bool:
    """Code, not only a comment or a string literal (check 3)."""
    toks = _collapse_fstrings(_tokens(text))
    return bool(toks) and not all(t.type == tokenize.STRING or t.string in (",", "(", ")") for t in toks)


def _names(text: str) -> set:
    """Identifiers a line binds or reads (Ruling F3): keywords and builtins out; a name used only as a dotted
    receiver (`os` in `os.getenv(...)`) out; names a `for` on the line binds out; a keyword-argument NAME
    (`timeout` in `f(timeout=5)`) out — its value still counts (fix I2). Tokenizing is per shown line, so a
    continuation line reads as depth 0 even when it is really inside a call opened on an earlier line; a NAME
    followed by `=` there is still a kwarg name when the line's own bracket balance is negative (it closes more
    than it opens — e.g. a lone `timeout=5)`), or when the NAME is the line's first token and the line ends with
    `,` (e.g. a black-formatted `data=token,`) (fix R1) — but only when the line opens no bracket or the `=`
    touches the NAME (kwarg spacing), so the binding `token = os.environ.get("K",` keeps `token` (fix F1)."""
    toks = _tokens(text)
    loop, bound = set(), False
    for t in toks:
        if t.type == tokenize.NAME and t.string == "for":
            bound = True
        elif t.type == tokenize.NAME and t.string == "in":
            bound = False
        elif bound and t.type == tokenize.NAME:
            loop.add(t.string)
    net = sum(1 for t in toks if t.string in ("(", "[", "{")) - sum(1 for t in toks if t.string in (")", "]", "}"))
    ends_comma = bool(toks) and toks[-1].string == ","
    free: set = set()
    depth = 0
    for i, t in enumerate(toks):
        if t.string in ("(", "[", "{"):
            depth += 1
        elif t.string in (")", "]", "}"):
            depth -= 1
        if t.type != tokenize.NAME or t.string in _NOT_NAMES or t.string in loop:
            continue
        if i and toks[i - 1].string == ".":
            continue                                          # an attribute, not a variable
        if i + 1 < len(toks) and toks[i + 1].string == ".":
            continue                                          # only a receiver here
        if i + 1 < len(toks) and toks[i + 1].string == "=" and (
                depth > 0 or net < 0 or (ends_comma and i == 0 and (net <= 0 or toks[i + 1].start == t.end))):
            continue                                          # a keyword-argument name, not a read
        free.add(t.string)
    return free


def _index(entry) -> dict:
    idx: dict[str, list] = {}
    for n, text in (entry.get("lines") or {}).items():
        idx.setdefault(_norm(text), []).append(n)
    return idx


def _hits(idx, pairs, strings) -> list | None:
    """Line numbers of every quoted line in one file, or None when some quoted line is not there. A matched
    occurrence whose line number lies inside a string constant does not count (fix I3b)."""
    out = []
    for raw, stripped in pairs:
        found = [n for n in (idx.get(raw) or idx.get(stripped) or []) if n not in strings]
        if not found:
            return None
        out.append(found)
    return out


def _bound(text: str) -> set:
    """Names a line binds (plan review I6): targets before a top-level `=` (not `==`, `<=`, ...); for a `:=` at
    any depth, ONLY the single NAME directly before it (fix R3 — `if check(k := f()):` binds `k`, not `check`;
    fix m6 for the parenthesised case); names between `for` and `in`; and the name after `as`. Never a keyword,
    a builtin, or a dotted part."""
    toks = _tokens(text)
    out, depth, eq, walrus = set(), 0, None, False
    for i, t in enumerate(toks):
        if t.string in ("(", "[", "{"):
            depth += 1
        elif t.string in (")", "]", "}"):
            depth -= 1
        elif t.type == tokenize.OP and t.string == ":=":
            eq, walrus = i, True
            break
        elif depth == 0 and t.type == tokenize.OP and t.string == "=":
            eq = i
            break
    names = lambda seq: {t.string for k, t in seq if t.type == tokenize.NAME and t.string not in _NOT_NAMES
                         and not (k and toks[k - 1].string == ".") and not (k + 1 < len(toks)
                                                                             and toks[k + 1].string == ".")}
    if eq is not None:
        if walrus:
            if eq:
                out |= names([(eq - 1, toks[eq - 1])])
        else:
            out |= names([(k, toks[k]) for k in range(eq)])
    for k, t in enumerate(toks):
        if t.string == "for":
            j = k + 1
            while j < len(toks) and toks[j].string != "in":
                j += 1
            out |= names([(m, toks[m]) for m in range(k + 1, j)])
        elif t.string == "as" and k + 1 < len(toks):
            out |= names([(k + 1, toks[k + 1])])
    return out


def _near(a, b, scopes) -> bool:
    """Rule (b): the same scope other than module, or both module-level within _MODULE_SPAN lines."""
    sa, sb = scopes.get(a), scopes.get(b)
    return sa is not None and sa == sb and (sa != "module" or abs(a - b) <= _MODULE_SPAN)


def _cuts(entry) -> dict:
    """{line: string-tail column (int) or f-string field code (str)} for `_text_at`; a tail wins (fix G1)."""
    return {**(entry.get("fields") or {}), **(entry.get("tails") or {})}


def _text_at(n, lines, tails) -> str:
    """The text to tokenize for shown line `n` (fix R3): from its recorded string-tail column onward when one is
    present (a line that is really the tail of a multi-line string, with real code following the string's close
    on that same line — reviewer's "tails"); for a line inside an f-string, only its `{...}` field code
    (reviewer's "fields", fix G1); else the whole line. `tails` is `_cuts(entry)`."""
    text = lines.get(n, "")
    cut = tails.get(n)
    if isinstance(cut, str):
        return cut
    return text[cut:] if cut is not None else text


def _anchors(hits, lines, tails) -> list:
    """Matched lines that can support Connected — its names and its position both (fix I1): live, not a bare
    `import`/`from ... import` line, and carrying at least one name after `_names`'s exclusions. A quoted padding
    line (`pass`, a lone `)`, a copied import line) adds neither a name nor a position."""
    out = []
    for n in {m for ns in hits for m in ns}:
        text = _text_at(n, lines, tails)
        if _live(text) and not _IMPORT_LINE.match(text) and _names(text):
            out.append(n)
    return out


def _connected(src_hits, snk_hits, entry) -> bool:
    """Spec F §3.3 check 4 (user choice G1, plan review I6): (a) the ends share an identifier; or (b) a source line
    and a sink line are near (_near); or (c) ONE hop: a name bound on a source line is read on a shown, live line R
    of the same file and not inside a string (fix F3), and R is near some sink line (R may be the sink line). No
    hop without scopes; never two.
    Only anchor lines (fix I1) supply names or positions for (a)/(b); the hop's hit end is likewise anchor-only."""
    lines = entry.get("lines") or {}
    tails = _cuts(entry)
    src = _anchors(src_hits, lines, tails)
    snk = _anchors(snk_hits, lines, tails)
    if not src or not snk:
        return False
    if (set().union(*(_names(_text_at(n, lines, tails)) for n in src))
            & set().union(*(_names(_text_at(n, lines, tails)) for n in snk))):
        return True
    scopes = entry.get("scopes")
    if not scopes:
        return False
    if any(_near(a, b, scopes) for a in src for b in snk):
        return True
    bound = set().union(*(_bound(_text_at(n, lines, tails)) for n in src))
    if not bound:
        return False
    strings = set(entry.get("strings") or []) - set(entry.get("fields") or {})   # field code may read (N1)
    readers = [r for r in lines if r not in src and r not in strings and _live(_text_at(r, lines, tails))
               and bound & _names(_text_at(r, lines, tails))]
    return any(r == b or _near(r, b, scopes) for r in readers for b in snk)


_GROUP_CAP = 64          # K1: at most this many anchor-bearing groups per end are paired below


def _groups(hits, lines) -> list:
    """K1: one end's matched line numbers (all occurrences of all its quoted lines) split into contiguous
    groups. Sorted n < m share a group only when every shown line strictly between them exists in `lines` and is
    blank or comment-only (`#...`); a line that is not shown at all breaks the group. Without this, Connected and
    Kind evidence could be stitched together from scattered, unrelated occurrences of the quoted text."""
    ns = sorted({m for xs in hits for m in xs})
    groups: list = []
    cur: list = []
    for n in ns:
        if cur and all(k in lines and (not lines[k].strip() or lines[k].strip().startswith("#"))
                       for k in range(cur[-1] + 1, n)):
            cur.append(n)
        else:
            if cur:
                groups.append(cur)
            cur = [n]
    if cur:
        groups.append(cur)
    return groups


def _anchor_groups(hits, lines, tails) -> list:
    """This end's groups (K1) that carry at least one anchor line, capped to the first `_GROUP_CAP` in line
    order -- bounds the O(groups) pairing work in `_gate_file`."""
    out = []
    for g in _groups(hits, lines):
        if _anchors([g], lines, tails):
            out.append(g)
            if len(out) >= _GROUP_CAP:
                break
    return out


_LEVEL_RANK = {"connected": 1, "src-kind": 2, "snk-kind": 2, "pair": 3}


def _gate_file(verdict, path, entry, src_hits, snk_hits) -> str:
    """Checks 3-6 for one candidate file (Live, Connected, Kind, Pair); "" when this file makes the chain stand.
    K1: Connected and Kind are checked per contiguous group of matched lines (`_groups`), not across all of an
    end's occurrences at once -- the chain stands only when SOME (source group, sink group) pair passes Connected
    and then Kind on that pair's own texts. When no pair passes, the reason returned is from whichever pair got
    furthest (Connected < Kind < Pair), preferring a source-Kind reason over a sink-Kind one at the same depth."""
    cls = entry.get("cls")
    if cls == "not-shipped":
        return f"chain is in not-shipped code ({path})"
    if cls == "inert":
        return f"chain is in inert code ({path})"                # fix I4
    if cls in (None, "unknown"):
        return f"chain is in unclassified code ({path})"
    lines = entry.get("lines") or {}
    tails = _cuts(entry)
    if not any(_live(_text_at(n, lines, tails)) for ns in src_hits for n in ns):
        return "source is only a comment or a string"
    if not any(_live(_text_at(n, lines, tails)) for ns in snk_hits for n in ns):
        return "sink is only a comment or a string"
    src_groups = _anchor_groups(src_hits, lines, tails)
    snk_groups = _anchor_groups(snk_hits, lines, tails)
    if not src_groups or not snk_groups:
        return "no dataflow shown between source and sink"
    strings = set(entry.get("strings") or [])
    kind_lines = {n: t for n, t in lines.items() if n not in strings}       # import table skips string lines (R8-1)
    table = _import_table(t for t in kind_lines.values() if t.lstrip().startswith(("import ", "from ")))
    best_rank, best_level, best_reason = -1, None, None
    for sg in src_groups:
        for kg in snk_groups:
            if not _connected([sg], [kg], entry):
                level, reason = "connected", "no dataflow shown between source and sink"
            else:
                reason = _kinds(verdict, [_text_at(n, lines, tails) for n in sg],
                                [_text_at(n, lines, tails) for n in kg], table)
                if reason == "":
                    return ""
                level = "src-kind" if reason.startswith("source quoted") else \
                    "snk-kind" if reason.startswith("sink quoted") else "pair"
            rank = _LEVEL_RANK[level]
            if rank > best_rank or (rank == best_rank and level == "src-kind" and best_level == "snk-kind"):
                best_rank, best_level, best_reason = rank, level, reason
    return best_reason


def gate(verdict, shown) -> str:
    """Why a malicious verdict's chain does not stand, or "" when it does (spec F §3.3). Checks in order, the first
    failure is the reason: Present, Found (one file), Live, Connected, Kind, Pair. Every candidate file (both ends
    found there) is gated; the chain stands if any of them passes, else the first candidate's reason is returned
    (fix I5)."""
    if not cited(verdict):
        return "no chain quoted (source and sink)"
    src, snk = clean(verdict.chain_source), clean(verdict.chain_sink)
    files = [(p, e, _index(e), set(e.get("strings") or [])) for p, e in (shown or {}).items()
             if isinstance(e, dict)]
    src_in = [(p, e, h) for p, e, idx, strings in files if (h := _hits(idx, src, strings)) is not None]
    snk_in = {p: h for p, e, idx, strings in files if (h := _hits(idx, snk, strings)) is not None}
    if not src_in:
        return "source not found in the shown code"
    if not snk_in:
        return "sink not found in the shown code"
    both = [(p, e, h) for p, e, h in src_in if p in snk_in]
    if not both:
        return "source and sink are in different files"
    first_reason = None
    for path, entry, src_hits in both:
        reason = _gate_file(verdict, path, entry, src_hits, snk_in[path])
        if reason == "":
            return ""
        if first_reason is None:
            first_reason = reason
    return first_reason


PAIRS = frozenset({("secret-read", "send"), ("payload", "exec"), ("fetch", "exec"), ("fetch", "write-and-run"),
                   ("payload", "write-and-run")})
_CRED = re.compile(r"\.ssh|\.aws|\.pypirc|\.netrc|\.git-credentials|\.npmrc|\.docker/config\.json|\.kube/config|"
                   r"keyring|/proc/[^/'\"]+/(?:environ|cmdline)|Cookies|Login Data|Local State|key4\.db|wallet\.dat|"
                   r"Exodus|Electrum")
_PERSIST = re.compile(r"\.pth$|(?:site|user)customize\.py$|(?:^|/)\.(?:bashrc|zshrc|profile|bash_profile)$|"
                      r"crontab|/etc/cron|systemd/.*\.service$|LaunchAgents/")
_BLOB = re.compile(r"^(?:(?=.*\d)(?=.*[A-Z])(?=.*[a-z])[A-Za-z0-9+/=_-]{128,}|(?:[0-9a-fA-F]{2}){65,})$")
_DECODE = {"b64decode", "urlsafe_b64decode", "b16decode", "b32decode", "a85decode", "b85decode", "unhexlify",
           "decompress", "fromhex", "a2b_base64", "a2b_hex", "a2b_uu"}
_NET_ROOTS = {"requests", "httpx", "urllib", "urllib3", "aiohttp", "socket", "http", "smtplib", "ftplib"}
_NET_FUNCS = {"urlopen", "urlretrieve", "Request", "create_connection"}
_NET_PRIMS = {"urlopen", "urlretrieve", "Request", "get", "post", "put", "patch", "delete", "head", "request",
              "stream", "socket", "create_connection", "connect", "send", "sendall", "sendto", "recv", "Client",
              "AsyncClient", "Session", "ClientSession", "PoolManager", "HTTPConnection", "HTTPSConnection", "SMTP",
              "SMTP_SSL", "FTP"}
_FETCH_METHODS = {"recv", "recv_into", "get", "read", "urlopen", "urlretrieve"}
_SEND_METHODS = {"send", "sendall", "sendto", "request", "post", "put", "patch", "sendmail"}
_PROCESS = {"os.system", "os.popen", "subprocess.Popen", "subprocess.run", "subprocess.call",
            "subprocess.check_output", "subprocess.check_call", "subprocess.getoutput", "subprocess.getstatusoutput"}
_WRITE_MODES = {"w", "wb", "a", "ab", "w+", "wb+", "a+", "ab+", "x", "xb"}


def _import_table(lines) -> dict:
    """name -> full dotted target from the shown file's import lines (Ruling F2). Each line is split on a
    top-level `;` first (K2: `import os; import subprocess as sp` -> `sp` maps to `subprocess`, not `os`)."""
    table = {}
    for text in lines:
        toks = [t.string for t in _tokens(text)]
        stmts, cur, depth = [], [], 0
        for tok in toks:
            if tok in ("(", "[", "{"):
                depth += 1
            elif tok in (")", "]", "}"):
                depth -= 1
            if tok == ";" and depth == 0:
                stmts.append(cur)
                cur = []
            else:
                cur.append(tok)
        stmts.append(cur)
        for toks in stmts:
            if toks[:1] == ["import"]:
                for part in " ".join(toks[1:]).split(","):
                    words = part.replace(" . ", ".").split()
                    if words:
                        table[words[-1] if "as" in words else words[0].split(".")[0]] = words[0] if "as" in words \
                            else words[0].split(".")[0]
            elif toks[:1] == ["from"] and "import" in toks:
                mod = "".join(toks[1:toks.index("import")])
                for part in " ".join(toks[toks.index("import") + 1:]).strip("() ").split(","):
                    words = part.split()
                    if words:
                        table[words[-1]] = f"{mod}.{words[0]}"
    return table


def _facts(text, table) -> dict:
    toks = _tokens(text)
    calls, names = [], set()
    i = 0
    while i < len(toks):
        if toks[i].type == tokenize.NAME and not (i and toks[i - 1].string == "."):
            parts, j = [toks[i].string], i + 1
            while j + 1 < len(toks) and toks[j].string == "." and toks[j + 1].type == tokenize.NAME:
                parts.append(toks[j + 1].string)
                j += 2
            root = table.get(parts[0], parts[0])
            full = ".".join([root] + parts[1:])
            names.add(full)
            if j < len(toks) and toks[j].string == "(":
                calls.append(full)
            i = j
        else:
            i += 1
    methods = {toks[k].string for k in range(1, len(toks) - 1)
               if toks[k].type == tokenize.NAME and toks[k - 1].string == "." and toks[k + 1].string == "("}
    strings = []
    for t in toks:
        if t.type == tokenize.STRING:
            s = t.string.lstrip("rRbBuUfF")
            strings.append(s.strip("'\"") if len(s) >= 2 else s)
        elif t.type == _FSTRING_MIDDLE:
            strings.append(t.string)
    fstr = any(t.type == tokenize.STRING and t.string[:1] in "fF" for t in toks) or \
        any(t.type == _FSTRING_START for t in toks)
    ops = {t.string for t in toks if t.type == tokenize.OP}
    return {"calls": calls, "names": names, "methods": methods, "strings": strings, "ops": ops, "fstr": fstr}


def _last(n):
    return n.rsplit(".", 1)[-1]


def _net_call(c):
    return (c.split(".", 1)[0] in _NET_ROOTS and _last(c) in _NET_PRIMS) or _last(c) in _NET_FUNCS


def _is_exec(f):
    return (any(c in {"exec", "eval", "compile", "__import__"} or c in _PROCESS
                or c.split(".", 1)[0] in {"ctypes", "runpy", "importlib"} or c.startswith(("os.exec", "os.spawn"))
                for c in f["calls"])
            or any(n.split(".", 1)[0] == "ctypes" for n in f["names"]) or "exec_module" in f["methods"])


def _is_write(f):
    return (any(_last(c) == "open" for c in f["calls"]) and any(s in _WRITE_MODES for s in f["strings"])) \
        or bool({"write_bytes", "write_text"} & f["methods"]) \
        or any(c.startswith("shutil.copy") or c == "shutil.move" for c in f["calls"])


def _evidence(kind, texts, table) -> bool:
    fs = [_facts(t, table) for t in texts]
    if kind == "secret-read":
        return any(any(n == "os.environ" or n.startswith("os.environ.") or _last(n) == "getenv"
                       or n.split(".", 1)[0] == "keyring" for n in f["names"])
                   or any(_CRED.search(s) for s in f["strings"]) for f in fs)
    if kind == "payload":
        return any(any(_last(c) in _DECODE or c == "codecs.decode"
                       or (_last(c) in ("loads", "load") and c.split(".", 1)[0] in ("pickle", "marshal", "dill"))
                       for c in f["calls"])
                   or bool(_DECODE & f["methods"]) or ("^" in f["ops"] and "[" in f["ops"])
                   or any(_BLOB.match(s.strip()) for s in f["strings"]) for f in fs)
    if kind == "fetch":
        return any(any(_net_call(c) for c in f["calls"]) or bool(_FETCH_METHODS & f["methods"]) for f in fs)
    if kind == "send":
        return any(any(_net_call(c) for c in f["calls"]) or bool(_SEND_METHODS & f["methods"])
                   or any(_last(c) in ("getaddrinfo", "gethostbyname") and ("+" in f["ops"] or f["fstr"])
                          for c in f["calls"]) for f in fs)
    if kind == "exec":
        return any(_is_exec(f) for f in fs)
    if kind == "write-and-run":
        writes = any(_is_write(f) for f in fs)
        runs = any(_is_exec(f) or any("chmod" in _last(c) for c in f["calls"]) for f in fs)
        persist = any(_PERSIST.search(s) for f in fs for s in f["strings"])
        return writes and (runs or persist)
    return False


def _kinds(verdict, src_lines, snk_lines, table) -> str:
    """Checks 5 (Kind) and 6 (Pair). `table` is `_gate_file`'s import table (K1: built once, reused per group)."""
    if not _evidence(verdict.source_kind, src_lines, table):
        return f"source quoted as {verdict.source_kind}, but the quoted lines show no {verdict.source_kind}"
    if not _evidence(verdict.sink_kind, snk_lines, table):
        return f"sink quoted as {verdict.sink_kind}, but the quoted lines show no {verdict.sink_kind}"
    if (verdict.source_kind, verdict.sink_kind) not in PAIRS:
        return f"{verdict.source_kind} → {verdict.sink_kind} is not a chain that makes a release malicious"
    return ""
