"""Spec F §3.3: the chain gate. A malicious verdict stands only when the model quoted a chain the shown code
contains. Pure: it reads the verdict's quotes and `shown` (the lines the model was shown), never package bytes, and
never runs or fetches anything."""
import builtins, io, keyword, re, tokenize

SOURCE_KINDS = ("secret-read", "payload", "fetch", "none")
SINK_KINDS = ("send", "exec", "write-and-run", "none")
QUOTE_MAX = 2_000

_MODULE_SPAN = 50
_PREFIX = re.compile(r"^(?:[+-](?=\s|$)|L?\d+:)")
_NOISE = {tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT, tokenize.ENDMARKER, tokenize.COMMENT}
_NOT_NAMES = set(keyword.kwlist) | set(getattr(keyword, "softkwlist", [])) | set(dir(builtins))


def _norm(s: str) -> str:
    return " ".join(s.split())


def clean(quote) -> list:
    """A quote as (raw, prefix-stripped) normalised line pairs: blank lines, `...`, `@@` position lines and copied
    file headings dropped (spec F §3.3 check 2). Both forms are tried, so a real `12: 'x'` line still matches."""
    out = []
    for ln in (quote if isinstance(quote, str) else "").split("\n"):
        s = ln.strip()
        if not s or s in ("...", "…") or s.startswith(("@@", "--- file:")):
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
    out = []
    try:
        for t in tokenize.generate_tokens(io.StringIO(text.strip() + "\n").readline):
            out.append(t)
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass
    return [t for t in out if t.type not in _NOISE]


def _live(text: str) -> bool:
    """Code, not only a comment or a string literal (check 3)."""
    toks = _tokens(text)
    return bool(toks) and not all(t.type == tokenize.STRING or t.string in (",", "(", ")") for t in toks)


def _names(text: str) -> set:
    """Identifiers a line binds or reads (Ruling F3): keywords and builtins out; a name used only as a dotted
    receiver (`os` in `os.getenv(...)`) out; names a `for` on the line binds out."""
    toks = _tokens(text)
    loop, bound = set(), False
    for t in toks:
        if t.type == tokenize.NAME and t.string == "for":
            bound = True
        elif t.type == tokenize.NAME and t.string == "in":
            bound = False
        elif bound and t.type == tokenize.NAME:
            loop.add(t.string)
    free: set = set()
    for i, t in enumerate(toks):
        if t.type != tokenize.NAME or t.string in _NOT_NAMES or t.string in loop:
            continue
        if i and toks[i - 1].string == ".":
            continue                                          # an attribute, not a variable
        if i + 1 < len(toks) and toks[i + 1].string == ".":
            continue                                          # only a receiver here
        free.add(t.string)
    return free


def _index(entry) -> dict:
    idx: dict[str, list] = {}
    for n, text in (entry.get("lines") or {}).items():
        idx.setdefault(_norm(text), []).append(n)
    return idx


def _hits(idx, pairs) -> list | None:
    """Line numbers of every quoted line in one file, or None when some quoted line is not there."""
    out = []
    for raw, stripped in pairs:
        found = idx.get(raw) or idx.get(stripped)
        if not found:
            return None
        out.append(found)
    return out


def _bound(text: str) -> set:
    """Names a line binds (plan review I6): targets before a top-level `=` / `:=` (not `==`, `<=`, ...), names
    between `for` and `in`, and the name after `as`. Never a keyword, a builtin, or a dotted part."""
    toks = _tokens(text)
    out, depth, eq = set(), 0, None
    for i, t in enumerate(toks):
        if t.string in "([{":
            depth += 1
        elif t.string in ")]}":
            depth -= 1
        elif depth == 0 and t.type == tokenize.OP and t.string in ("=", ":="):
            eq = i
            break
    names = lambda seq: {t.string for k, t in seq if t.type == tokenize.NAME and t.string not in _NOT_NAMES
                         and not (k and toks[k - 1].string == ".") and not (k + 1 < len(toks)
                                                                             and toks[k + 1].string == ".")}
    if eq is not None:
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


def _connected(src_hits, snk_hits, entry) -> bool:
    """Spec F §3.3 check 4 (user choice G1, plan review I6): (a) the ends share an identifier; or (b) a source line
    and a sink line are near (_near); or (c) ONE hop: a name bound on a source line is read on a shown, live line R
    of the same file, and R is near some sink line (R may be the sink line). No hop without scopes; never two."""
    lines = entry.get("lines") or {}
    src = [n for ns in src_hits for n in ns]
    snk = [n for ns in snk_hits for n in ns]
    if set().union(*(_names(lines[n]) for n in src)) & set().union(*(_names(lines[n]) for n in snk)):
        return True
    scopes = entry.get("scopes")
    if not scopes:
        return False
    if any(_near(a, b, scopes) for a in src for b in snk):
        return True
    bound = set().union(*(_bound(lines[n]) for n in src))
    if not bound:
        return False
    readers = [r for r, text in lines.items() if r not in src and _live(text) and bound & _names(text)]
    return any(r == b or _near(r, b, scopes) for r in readers for b in snk)


def gate(verdict, shown) -> str:
    """Why a malicious verdict's chain does not stand, or "" when it does (spec F §3.3). Checks in order, the first
    failure is the reason: Present, Found (one file), Live, Connected, Kind, Pair."""
    if not cited(verdict):
        return "no chain quoted (source and sink)"
    src, snk = clean(verdict.chain_source), clean(verdict.chain_sink)
    files = [(p, e, _index(e)) for p, e in (shown or {}).items() if isinstance(e, dict)]
    src_in = [(p, e, idx, h) for p, e, idx in files if (h := _hits(idx, src)) is not None]
    snk_in = {p: h for p, e, idx in files if (h := _hits(idx, snk)) is not None}
    if not src_in:
        return "source not found in the shown code"
    if not snk_in:
        return "sink not found in the shown code"
    both = [(p, e, h) for p, e, _idx, h in src_in if p in snk_in]
    if not both:
        return "source and sink are in different files"
    path, entry, src_hits = both[0]
    snk_hits = snk_in[path]
    cls = entry.get("cls")
    if cls == "not-shipped":
        return f"chain is in not-shipped code ({path})"
    if cls in (None, "unknown"):
        return f"chain is in unclassified code ({path})"
    lines = entry.get("lines") or {}
    if not any(_live(lines[n]) for ns in src_hits for n in ns):
        return "source is only a comment or a string"
    if not any(_live(lines[n]) for ns in snk_hits for n in ns):
        return "sink is only a comment or a string"
    if not _connected(src_hits, snk_hits, entry):
        return "no dataflow shown between source and sink"
    return _kinds(verdict, [lines[n] for ns in src_hits for n in ns], [lines[n] for ns in snk_hits for n in ns],
                  lines)


def _kinds(verdict, src_lines, snk_lines, lines) -> str:
    return ""        # Task 8
