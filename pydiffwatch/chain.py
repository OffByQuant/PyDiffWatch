"""Spec F §3.3: the chain gate. A malicious verdict stands only when the model quoted a chain the shown code
contains. Pure: it reads the verdict's quotes and `shown` (the lines the model was shown), never package bytes, and
never runs or fetches anything."""
import bisect, builtins, io, keyword, re, tokenize

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
    except (tokenize.TokenError, IndentationError, SyntaxError, UnicodeDecodeError, ValueError):
        pass   # UnicodeDecodeError: e.g. a "\r" before a U+2028 (Task 10 fix J1)
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


_HEADERS = {"if", "elif", "else", "while", "for", "with", "try", "except", "finally"}
_NO_READS = {"import", "from", "global", "nonlocal", "del"}
_NOT_SOFT = {"=", ".", ":=", ",", ")", "]", "}", ":", ";", "+=", "-=", "*=", "/=", "//=", "%=", "**=", "@=", "&=",
             "|=", "^=", ">>=", "<<="}       # after `match`/`case`, these make it a plain identifier
_OPEN, _CLOSE = ("(", "[", "{"), (")", "]", "}")


def _op(t, *s) -> bool:
    return t.type == tokenize.OP and t.string in s


def _reads(text: str) -> set:
    """Names a line really reads (Q1; rounds 4-5). Per `;`-separated statement, a name is read when it occurs,
    outside a binding position and outside a scope that binds it, more often than it occurs as a target. Targets
    are bare names, including inside grouping brackets (`(a, b) = f()`): before the last top-level `=` of a
    non-continuation line (the name before `:` for an annotated one, whose annotation is read); directly before
    `:=`; between a statement's `for` and `in`; after `as`. Binding positions are never counted: the name after
    `def`/`class`, `def`/`lambda` parameters, comprehension loop targets, a `case` capture, a keyword-argument
    name, and every name of an `import`/`from`/`global`/`nonlocal`/`del` statement (T4a: only those positions --
    a default value `token=token` reads token). Scopes on the line: a comprehension's targets are local inside
    its brackets except in its first iterable; a lambda's parameters inside its body; a one-line `def`'s
    parameters and a compound header's targets (`for i in r: out[i] = x`) in the body after the header's `:`.
    A continuation line (bracket balance < 0, or ending `,` without opening a bracket and without a tuple-target
    assignment, T5) has no targets. Structure is matched by token type (`ops`: OP strings, `nm`: NAME strings),
    so f-string text never counts (T3). A dotted receiver or a called name is a read; an attribute, a keyword or a
    builtin is not. Every pass is linear in the line's tokens: no span is rescanned per nesting level (T2)."""
    toks = _tokens(text)
    if not toks:
        return set()
    ops = [t.string if t.type == tokenize.OP else "" for t in toks]
    nm = [t.string if t.type == tokenize.NAME else "" for t in toks]
    depths, match, opened, depth = [], [len(toks)] * len(toks), [], 0
    first_eq = comma_before_eq = None
    for i, o in enumerate(ops):
        if o in _CLOSE:
            depth -= 1
            if opened:
                match[opened.pop()] = i
        depths.append(depth)
        if o in _OPEN:
            depth += 1
            opened.append(i)
        elif depth == 0 and first_eq is None and o:
            if o == ",":
                comma_before_eq = True
            elif o == "=" and i and toks[i - 1].end != toks[i].start:
                first_eq = i
    tuple_assign = first_eq is not None and bool(comma_before_eq)
    cont = depth < 0 or (ops[-1] == "," and depth <= 0 and not tuple_assign)
    line = (toks, ops, nm, depths, match, _line_scopes(toks, ops, nm, depths))
    out: set = set()
    start = 0
    for i in range(len(toks) + 1):
        if i == len(toks) or (ops[i] == ";" and depths[i] <= 0):
            _stmt_reads(line, start, i, cont, out)
            start = i + 1
    return out


def _grouping(toks, i) -> bool:
    """Whether the bracket at i groups (a tuple/list display) rather than calls or subscripts."""
    prev = toks[i - 1] if i else None
    return toks[i].string != "{" and not (prev is not None and (
        (prev.type == tokenize.NAME and not keyword.iskeyword(prev.string))
        or prev.type == tokenize.STRING or (prev.type == tokenize.OP and prev.string in (")", "]"))))


def _line_scopes(toks, ops, nm, depths) -> dict:
    """One pass: comprehension loop targets (skipped positions, and the names each comprehension's brackets
    bind), where each comprehension's first iterable starts and ends, and each lambda's parameters and colon."""
    comp_names: dict = {}               # opener -> names its `for` targets bind
    first_in: dict = {}                 # the `in` token opening an opener's first iterable -> opener
    resume: dict = {}                   # the `for`/`if` closing that iterable -> opener
    lam_colon: dict = {}                # a lambda's `:` -> its parameter names
    skip: set = set()
    opened: list = []
    has_first: set = set()
    region: dict = {}                   # depth -> opener whose for-target region is open at that depth
    pend: dict = {}                     # depth -> pending comprehension `for`s
    wait: dict = {}                     # depth -> opener waiting for its first iterable to end
    lams: dict = {}                     # depth -> open lambda headers [(index, params)]
    n = len(toks)
    for i in range(n):
        o, w, d = ops[i], nm[i], depths[i]
        if o:
            if o in _CLOSE:
                if opened:
                    opened.pop()
                for m in (region, pend, wait, lams):
                    m.pop(d + 1, None)
            elif o in _OPEN:
                if region.get(d) is not None and _grouping(toks, i):
                    region[d + 1] = region[d]
                opened.append(i)
            elif o == ":" and lams.get(d):
                lam_colon[i] = lams[d].pop()[1]
            continue
        if not w:
            continue
        if w == "for" and opened and d == depths[opened[-1]] + 1:
            pend.setdefault(d, []).append(i)
            region[d] = opened[-1]
            comp_names.setdefault(opened[-1], set())
            if wait.get(d) is not None:
                resume[i] = wait.pop(d)
        elif w == "if" and wait.get(d) is not None:
            resume[i] = wait.pop(d)
        elif w == "in" and pend.get(d):
            pend[d].pop()
            region.pop(d, None)
            if opened and opened[-1] not in has_first:
                has_first.add(opened[-1])
                first_in[i] = opened[-1]
                wait[d] = opened[-1]
        elif w == "lambda":
            lams.setdefault(d, []).append((i, set()))
        elif keyword.iskeyword(w):
            continue
        elif region.get(d) is not None:
            if not (i and ops[i - 1] == ".") and not (i + 1 < n and ops[i + 1] in (".", "[", "(")):
                skip.add(i)
                comp_names[region[d]].add(w)
        elif lams.get(d) and i and (nm[i - 1] == "lambda" or ops[i - 1] in (",", "*", "**")):
            skip.add(i)
            lams[d][-1][1].add(w)
    return {"comp": comp_names, "first_in": first_in, "resume": resume, "lam": lam_colon, "skip": skip}


def _grouped_names(toks, a, b) -> list:
    """Indices of bare names in toks[a:b] that are binding targets: not dotted, not subscripted or called, and
    inside only grouping brackets (a tuple/list display), never inside a call's or subscript's brackets."""
    out, stack, calls = [], [], 0       # calls: open brackets that call or subscript (O(1) per token)
    for i in range(a, b):
        t = toks[i]
        if t.type == tokenize.OP and t.string in _OPEN:
            stack.append(i == a or _grouping(toks, i))
            calls += not stack[-1]
        elif t.type == tokenize.OP and t.string in _CLOSE:
            if stack:
                calls -= not stack.pop()
        elif (t.type == tokenize.NAME and not calls and not (i > a and _op(toks[i - 1], "."))
              and not (i + 1 < b and _op(toks[i + 1], ".", "[", "("))):
            out.append(i)
    return out


def _stmt_reads(line, a, b, cont, out) -> None:
    """`_reads` for one statement, toks[a:b]: a one-line compound statement is walked header by header (a
    loop), carrying the scopes the line opens (a stack plus a count of how many active scopes bind each name)."""
    toks, ops, nm, depths, match, info = line
    first_in, resume, comps, lams, lskip = info["first_in"], info["resume"], info["comp"], info["lam"], info["skip"]
    shadow: dict = {}
    stack: list = []                    # [kind, names, depth or end, active]
    by_opener: dict = {}

    def cover(names, sign):
        for x in names:
            shadow[x] = shadow.get(x, 0) + sign

    def push(kind, names, where):
        s = [kind, names, where, True]
        stack.append(s)
        cover(names, 1)
        return s

    def pop():
        s = stack.pop()
        if s[3]:
            cover(s[1], -1)
    while True:
        while a < b and nm[a] == "async":
            a += 1
        if a >= b or nm[a] in _NO_READS:
            return
        first, d0 = nm[a], depths[a]
        colon = next((i for i in range(a, b) if ops[i] == ":" and depths[i] == d0), None)
        soft = first in ("match", "case") and colon is not None and a + 1 < b and ops[a + 1] not in _NOT_SOFT
        skip: set = set()
        targets: list = []
        header: list = []               # names a compound header binds for its one-line body
        guard = None                    # where a case pattern's captures start to bind (its guard or `:`)
        params: set = set()
        body = None
        if first in ("def", "class"):
            skip.add(a + 1)
            if first == "def" and a + 2 < b and ops[a + 2] == "(":
                for i in range(a + 3, min(match[a + 2], b)):
                    if nm[i] and depths[i] == d0 + 1 and ops[i - 1] in ("(", ",", "*", "**"):
                        skip.add(i)
                        params.add(nm[i])
            body = colon
        elif first in _HEADERS or (soft and first == "match"):
            body = colon
            if first == "for":
                stop = colon if colon is not None else b
                j = next((i for i in range(a + 1, stop) if nm[i] == "in" and depths[i] == d0), stop)
                targets += _grouped_names(toks, a + 1, j)
        elif soft:
            body = colon
            guard = next((i for i in range(a + 1, colon) if nm[i] == "if" and depths[i] == d0), colon)
            for i in range(a + 1, guard):
                if (nm[i] and not keyword.iskeyword(nm[i]) and ops[i - 1] != "."
                        and not (i + 1 < b and ops[i + 1] in (".", "(", "="))):
                    skip.add(i)
                    params.add(nm[i])
        elif not cont:
            eqs = [i for i in range(a, b) if ops[i] == "=" and depths[i] == d0]
            if colon is not None and first != "lambda" and (not eqs or colon < eqs[0]):
                targets += _grouped_names(toks, a, colon)          # an annotated target; its annotation is read
            elif eqs:
                targets += _grouped_names(toks, a, eqs[-1])
        end = body if body is not None else b
        occ: dict = {}
        tgt_at = set(targets)
        tgt: dict = {}
        covered = a
        for i in range(a, end if body is None else end + 1):
            o, w, d = ops[i], nm[i], depths[i]
            while stack and (
                    (stack[-1][0] == "lam" and (d < stack[-1][2] or (d == stack[-1][2] and (
                        o in (",", ";") or (o == ":" and i not in lams)   # a nested lambda's `:` is not ours (N2)
                        or w in ("for", "async")))))
                    or (stack[-1][0] == "comp" and stack[-1][2] <= i)):
                pop()
            if i in first_in and first_in[i] in by_opener:
                s = by_opener[first_in[i]]
                if s[3]:
                    s[3] = False
                    cover(s[1], -1)
            elif i in resume and resume[i] in by_opener:
                s = by_opener[resume[i]]
                if not s[3] and s in stack:
                    s[3] = True
                    cover(s[1], 1)
            if o:
                if o in _OPEN and comps.get(i):
                    by_opener[i] = push("comp", comps[i], match[i])
                elif i in lams:
                    push("lam", lams[i], d)
            if i == guard:
                push("stmt", params, None)
            if i == end or not w:
                continue
            if w == "as" and i + 1 < end:
                if ops[i + 1] == "(":
                    if i + 1 >= covered:                      # nested `as (` regions are scanned once
                        covered = min(match[i + 1], end - 1) + 1
                        found = _grouped_names(toks, i + 1, covered)
                        tgt_at.update(found)
                        header += [nm[k] for k in found]
                elif nm[i + 1] and not (i + 2 < b and ops[i + 2] in (".", "[", "(")):
                    tgt_at.add(i + 1)
                    header.append(nm[i + 1])
            elif i + 1 < end and ops[i + 1] == ":=":
                tgt_at.add(i)
                header.append(w)
            if (w in _NOT_NAMES or i in skip or i in lskip or (i > a and ops[i - 1] in (".", "!"))
                    or shadow.get(w)):
                continue
            if i + 1 < len(ops) and ops[i + 1] == "=" and (d > d0 or cont) and (i == a or ops[i - 1] in ("(", ",")):
                continue                                      # a keyword-argument name (not `a: T = v`'s T)
            occ[w] = occ.get(w, 0) + 1
            if i in tgt_at:
                tgt[w] = tgt.get(w, 0) + 1
        out.update(x for x, c in occ.items() if c > tgt.get(x, 0))
        if body is None:
            return
        while stack and stack[-1][0] != "stmt":
            pop()
        if first == "for":
            header += [nm[k] for k in targets]
        if first == "def":
            push("stmt", params, None)
        elif not soft and header:
            push("stmt", set(header), None)
        a, cont = body + 1, False


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


def _depth(text: str) -> tuple:
    """(net, low): a line's bracket balance and the lowest point its running balance reaches (P3a)."""
    net = low = 0
    for t in _tokens(text):
        if t.type == tokenize.OP and t.string in ("(", "[", "{"):
            net += 1
        elif t.type == tokenize.OP and t.string in (")", "]", "}"):
            net -= 1
            low = min(low, net)
    return net, low


class _File:
    """One shown file's per-line facts, each computed at most once per gate call (P1: the gate stays linear in the
    shown lines -- no fact is recomputed per group or per pair)."""

    def __init__(self, entry):
        self.lines = entry.get("lines") or {}
        self.cuts = _cuts(entry)
        scopes = entry.get("scopes")
        self.scopes = scopes if isinstance(scopes, dict) else {}
        self.strings = set(entry.get("strings") or [])
        self.unreadable = self.strings - set(entry.get("fields") or {})   # field code may read (N1)
        local = entry.get("complocal")
        self.complocal = local if isinstance(local, dict) else {}           # multi-line comprehension names (T1)
        self._memo: dict = {}

    def text(self, n) -> str:
        return _text_at(n, self.lines, self.cuts)

    def _fact(self, fn, n):
        key = (fn, n)
        if key not in self._memo:
            self._memo[key] = fn(self.text(n))
        return self._memo[key]

    def live(self, n) -> bool:
        return self._fact(_live, n)

    def names(self, n) -> set:
        return self._fact(_names, n)

    def bound(self, n) -> set:
        return self._fact(_bound, n)

    def reads(self, n) -> set:
        local = self.complocal.get(n)
        return self._fact(_reads, n) - (set(local) if isinstance(local, (list, set, tuple)) else set())

    def reaches(self, binders, n) -> bool:
        """Q1/Q2: line n really reads a name some binder line binds, in a compatible scope -- `binders` holds
        (name, binder scope); a module-level binder reaches any scope, a function binder only its own scope."""
        s = self.scopes.get(n)
        return s is not None and any((m, "module") in binders or (s != "module" and (m, s) in binders)
                                     for m in self.reads(n))

    def binds(self, lines) -> set:
        """(name, scope) for every name the given lines bind; a line without a scope binds nothing here."""
        return {(m, self.scopes[n]) for n in lines if self.scopes.get(n) is not None for m in self.bound(n)}

    def depth(self, n) -> tuple:
        return (0, 0) if n in self.strings and n not in self.cuts else self._fact(_depth, n)

    def anchor(self, n) -> bool:
        """A matched line that can support Connected -- its names and its position both (fix I1): live, not a bare
        `import`/`from ... import` line, and carrying at least one name after `_names`'s exclusions. A quoted
        padding line (`pass`, a lone `)`, a copied import line) adds neither a name nor a position."""
        return self.live(n) and not _IMPORT_LINE.match(self.text(n)) and bool(self.names(n))


def _near_any(lines, scopes):
    """Rule (b) against a set of lines at once: `near(n)` is true when n and one of `lines` share a scope other than
    module, or are both module-level within _MODULE_SPAN lines -- set and bisect lookups, not a pairwise scan (P1)."""
    inner = {scopes.get(b) for b in lines} - {None, "module"}
    module = sorted(b for b in lines if scopes.get(b) == "module")

    def near(n) -> bool:
        s = scopes.get(n)
        if s is None:
            return False
        if s != "module":
            return s in inner
        i = bisect.bisect_left(module, n - _MODULE_SPAN)
        return i < len(module) and module[i] <= n + _MODULE_SPAN
    return near


def _connected(src, snk, f) -> bool:
    """Spec F §3.3 check 4 (user choice G1, plan review I6) between the lines of each end's evidence-bearing groups
    (P2): (a) the ends share an identifier; or (b) a source line and a sink line are near (same scope other than
    module, or both module-level within _MODULE_SPAN lines); or (c) ONE hop: a name bound on a source line is read
    on a shown, live line R of the same file and not inside a string (fix F3) -- really read (`_reads`), in a scope
    the binder reaches (Q2: the binder is module-level, or R shares its function scope) -- and R is near some sink
    line (R may be the sink line). No hop without scopes; never two. Only anchor lines (fix I1) supply names or
    positions for (a)/(b); the hop's hit end is likewise anchor-only."""
    src = [n for n in src if f.anchor(n)]
    snk = [n for n in snk if f.anchor(n)]
    if not src or not snk:
        return False
    if set().union(*map(f.names, src)) & set().union(*map(f.names, snk)):
        return True
    if not f.scopes:
        return False
    near = _near_any(snk, f.scopes)
    if any(near(a) for a in src):
        return True
    binders = f.binds(src)
    if not binders:
        return False
    src_set, snk_set = set(src), set(snk)
    return any(r in snk_set or near(r) for r in f.lines
               if r not in src_set and r not in f.unreadable and f.live(r) and f.reaches(binders, r))


_BRIDGE = 3              # P4: a group bridges at most this many consecutive blank/comment lines


def _groups(hits, lines) -> list:
    """K1: one end's matched line numbers (all occurrences of all its quoted lines) split into contiguous
    groups. Sorted n < m share a group only when at most _BRIDGE shown lines lie strictly between them (P4) and
    every one exists in `lines` and is blank or comment-only (`#...`); a line that is not shown at all breaks the
    group. Without this, Connected and Kind evidence could be stitched together from scattered, unrelated
    occurrences of the quoted text."""
    ns = sorted({m for xs in hits for m in xs})
    groups: list = []
    cur: list = []
    for n in ns:
        if cur and n - cur[-1] - 1 <= _BRIDGE and all(
                k in lines and (not lines[k].strip() or lines[k].strip().startswith("#"))
                for k in range(cur[-1] + 1, n)):
            cur.append(n)
        else:
            if cur:
                groups.append(cur)
            cur = [n]
    if cur:
        groups.append(cur)
    return groups


def _merged(groups, f) -> list:
    """P3: one end's groups, merged where the model quoted one statement or one flow and left lines out.
    (a) A group whose brackets are still open at its end (running balance, unmatched closers ignored) takes in the
    end's next group when every shown line between them keeps the brackets open -- the same statement. A statement
    that closes first, or a line not shown, stops the merge, so an open line near the sink cannot pull in a far,
    unrelated quoted line. Repeats while still open.
    (b) A later group joins an earlier group when one of its lines really reads (`_reads`) a name a line of the
    earlier group binds (`_bound`), in a compatible scope: the binder is module-level, or both lines share one
    function scope (Q1). Without scopes there is no name-merge; an assignment target alone is never a read."""
    runs: list = []                     # [lines, open brackets after its last line]
    for g in groups:
        bal = 0
        if runs and runs[-1][1] > 0:
            b, k = runs[-1][1], runs[-1][0][-1] + 1
            while k < g[0] and k in f.lines and b + f.depth(k)[1] > 0:
                b += f.depth(k)[0]
                k += 1
            if k == g[0]:
                bal = b
        if bal == 0:
            runs.append([[], 0])
        for n in g:
            net, low = f.depth(n)
            bal = max(bal + net, net - low)
        runs[-1][0].extend(g)
        runs[-1][1] = bal
    parent = list(range(len(runs)))

    def root(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i
    owner: dict = {}                    # (name, binder scope) -> the run that binds it
    for i, (g, _) in enumerate(runs):
        for n in g:
            s = f.scopes.get(n)
            if s is None:
                continue
            for m in f.reads(n):
                for key in ((m, "module"), (m, s)):
                    if key in owner and root(owner[key]) != root(i):
                        parent[root(owner[key])] = root(i)
        for key in f.binds(g):
            owner[key] = i
    out: dict = {}
    for i, (g, _) in enumerate(runs):
        out.setdefault(root(i), []).extend(g)
    return sorted(sorted(g) for g in out.values())


def _gate_file(verdict, path, entry, src_hits, snk_hits) -> str:
    """Checks 3-6 for one candidate file (Live, Kind, Connected, Pair); "" when this file makes the chain stand.
    K1/P2: each end's matched lines are split into groups (`_groups`, then `_merged`), and only groups whose own
    texts show that end's declared Kind evidence are kept, so evidence and connection are never stitched together
    from different, unrelated occurrences. Connected then runs over the kept groups of both ends at once: each of
    its rules is a union over lines, so this is exactly "some kept source group connects to some kept sink group",
    in time linear in the shown lines and with no pair cap for decoy copies to exhaust."""
    cls = entry.get("cls")
    if cls == "not-shipped":
        return f"chain is in not-shipped code ({path})"
    if cls == "inert":
        return f"chain is in inert code ({path})"                # fix I4
    if cls in (None, "unknown"):
        return f"chain is in unclassified code ({path})"
    f = _File(entry)
    if not any(f.live(n) for ns in src_hits for n in ns):
        return "source is only a comment or a string"
    if not any(f.live(n) for ns in snk_hits for n in ns):
        return "sink is only a comment or a string"
    kind_lines = {n: t for n, t in f.lines.items() if n not in f.strings}   # import table skips string lines (R8-1)
    table = _import_table(t for t in kind_lines.values() if t.lstrip().startswith(("import ", "from ")))
    ends = []
    for end, kind, hits in (("source", verdict.source_kind, src_hits), ("sink", verdict.sink_kind, snk_hits)):
        kept = [n for g in _merged(_groups(hits, f.lines), f) if _evidence(kind, [f.text(n) for n in g], table)
                for n in g]
        if not kept:
            return f"{end} quoted as {kind}, but the quoted lines show no {kind}"
        ends.append(kept)
    if not _connected(*ends, f):
        return "no dataflow shown between source and sink"
    if (verdict.source_kind, verdict.sink_kind) not in PAIRS:
        return f"{verdict.source_kind} → {verdict.sink_kind} is not a chain that makes a release malicious"
    return ""


def gate(verdict, shown) -> str:
    """Why a malicious verdict's chain does not stand, or "" when it does (spec F §3.3). Checks in order, the first
    failure is the reason: Present, Found (one file), Live, Kind, Connected, Pair (P2). Every candidate file (both ends
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
                   r"Exodus|Electrum|cookies\.sqlite|\.electrum|exodus\.wallet|logins\.json")
_PERSIST = re.compile(r"(?i:\.pth)$|(?:site|user)customize\.py$|(?:^|/)\.(?:bashrc|zshrc|profile|bash_profile)$|"
                      r"crontab|/etc/cron|systemd/.*\.service$|LaunchAgents/|(?:^|/)LaunchAgents(?:/|$)")
_BLOB = re.compile(r"^(?:(?=.*\d)(?=.*[A-Z])(?=.*[a-z])[A-Za-z0-9+/=_-]{128,}|(?:[0-9a-fA-F]{2}){65,})$")
_DECODE = {"b64decode", "urlsafe_b64decode", "b16decode", "b32decode", "a85decode", "b85decode", "unhexlify",
           "decompress", "fromhex", "a2b_base64", "a2b_hex", "a2b_uu"}
_NET_ROOTS = {"requests", "httpx", "urllib", "urllib3", "aiohttp", "socket", "http", "smtplib", "ftplib"}
_NET_FUNCS = {"urlopen", "urlretrieve", "Request", "create_connection"}
_NET_PRIMS = {"urlopen", "urlretrieve", "Request", "get", "post", "put", "patch", "delete", "head", "request",
              "stream", "socket", "create_connection", "connect", "send", "sendall", "sendto", "recv", "Client",
              "AsyncClient", "Session", "ClientSession", "PoolManager", "HTTPConnection", "HTTPSConnection", "SMTP",
              "SMTP_SSL", "FTP", "FTP_TLS", "build_opener"}
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
    root = c.split(".", 1)[0]
    return (root in _NET_ROOTS and _last(c) in _NET_PRIMS) or _last(c) in _NET_FUNCS \
        or (root == "urllib" and _last(c) == "open")          # an opener's open; plain `open` is never network


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
        persist = any(any(_PERSIST.search(s) for s in f["strings"])
                      or (any("systemd" in s for s in f["strings"])
                          and any(s.endswith(".service") for s in f["strings"])) for f in fs)
        return writes and (runs or persist)
    return False
