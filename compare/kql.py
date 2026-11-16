"""Kibana's query language, enough of it for Elastic's detection rules: `field: value`,
`field: (a or b)`, `field: *`, quoted phrases, `*` and `?` in a value, ranges, and/or/not, brackets.

    match = compile(text);  match(doc) -> bool        doc: nested dicts and lists

A value is compared without regard to case (a keyword field in Elasticsearch
is not, so a rule can match here and not there, never the reverse). A field
holding several values matches when any does."""
import fnmatch
import re

TOKEN = re.compile(r'\s*(?:(\()|(\))|(<=|>=|<|>|:)|"((?:[^"\\]|\\.)*)"|((?:[^\s():<>"\\]|\\.)+))')


class Error(Exception):
    pass


def values(doc, path):
    out = [doc]
    for part in path.split("."):
        nxt = []
        for v in out:
            if isinstance(v, list):
                v = [x for x in v]
            else:
                v = [v]
            for x in v:
                if isinstance(x, dict) and part in x:
                    y = x[part]
                    nxt.extend(y if isinstance(y, list) else [y])
        out = nxt
    return [v for v in out if v is not None]


def text(v):
    return ("true" if v else "false") if isinstance(v, bool) else str(v)


def compile(query):
    toks = []
    pos = 0
    query = query.strip()
    while pos < len(query):
        m = TOKEN.match(query, pos)
        if not m:
            raise Error(f"cannot read {query[pos:pos + 30]!r}")
        pos = m.end()
        if m.group(1):
            toks.append(("(", "("))
        elif m.group(2):
            toks.append((")", ")"))
        elif m.group(3):
            toks.append(("op", m.group(3)))
        elif m.group(4) is not None:
            toks.append(("quoted", re.sub(r"\\(.)", r"\1", m.group(4))))
        else:
            w = m.group(5)
            toks.append(("word", w) if w.lower() not in ("and", "or", "not") else (w.lower(), w))
    i = 0

    def peek(k=0):
        return toks[i + k] if i + k < len(toks) else (None, None)

    def take(kind=None):
        nonlocal i
        t = peek()
        if kind and t[0] != kind:
            raise Error(f"expected {kind}, got {t[1]!r}")
        i += 1
        return t

    def literal(kind, v):
        if kind == "quoted":
            want = v.lower()
            return lambda vs: any(text(got).lower() == want for got in vs)
        raw = re.sub(r"\\(.)", r"\1", v)
        if raw == "*":
            return lambda vs: bool(vs)
        if "*" in v or "?" in v:
            pat = re.compile(fnmatch.translate(raw.lower().replace("[", "[[]")), re.S)
            return lambda vs: any(pat.match(text(got).lower()) is not None for got in vs)
        want = raw.lower()
        return lambda vs: any(text(got).lower() == want for got in vs)

    def value_expr():  # the values after `field:`, as a test of the field's values: each term on any of them
        def atom():
            k, v = take()
            if k == "(":
                t = ors()
                take(")")
                return t
            if k == "not":
                t = atom()
                return lambda got: not t(got)
            if k in ("word", "quoted"):
                return literal(k, v)
            raise Error(f"a value, got {v!r}")

        def ands():
            ts = [atom()]
            while peek()[0] == "and":
                take()
                ts.append(atom())
            return ts[0] if len(ts) == 1 else (lambda got: all(t(got) for t in ts))

        def ors():
            ts = [ands()]
            while peek()[0] == "or" or peek()[0] in ("word", "quoted"):  # values side by side are any of
                if peek()[0] == "or":
                    take()
                ts.append(ands())
            return ts[0] if len(ts) == 1 else (lambda got: any(t(got) for t in ts))

        k, v = peek()
        if k == "(":
            take()
            t = ors()
            take(")")
            return t, True
        take()
        if k not in ("word", "quoted"):
            raise Error(f"a value, got {v!r}")
        return literal(k, v), False

    def primary():
        k, v = take()
        if k == "(":
            t = ors()
            take(")")
            return t
        if k == "not":
            t = primary()
            return lambda doc: not t(doc)
        if k != "word":
            raise Error(f"a field, got {v!r}")
        field = re.sub(r"\\(.)", r"\1", v)
        op = take("op")[1]
        if op == ":":
            t, grouped = value_expr()
            return lambda doc: bool(t(values(doc, field)))
        num = float(take("word")[1])
        cmp = {"<": lambda a: a < num, "<=": lambda a: a <= num, ">": lambda a: a > num, ">=": lambda a: a >= num}[op]

        def ranged(doc):
            for x in values(doc, field):
                try:
                    if cmp(float(x)):
                        return True
                except (TypeError, ValueError):
                    pass
            return False
        return ranged

    def ands():
        ts = [primary()]
        while peek()[0] == "and":
            take()
            ts.append(primary())
        return ts[0] if len(ts) == 1 else (lambda doc: all(t(doc) for t in ts))

    def ors():
        ts = [ands()]
        while peek()[0] == "or":
            take()
            ts.append(ands())
        return ts[0] if len(ts) == 1 else (lambda doc: any(t(doc) for t in ts))

    out = ors()
    if i != len(toks):
        raise Error(f"left over at {peek()[1]!r}")
    return out
