"""Sigma's macOS rules over the recordings.

    python3 -I sigma.py RECORDINGS > sigma-results.json

sigma.json is the rules as JSON (the repository's YAML, converted). A
process_creation rule reads each process start (Image, CommandLine,
ParentImage, ParentCommandLine); a file_event rule each file created, renamed
to, or written (TargetFilename, Image). Matching is Sigma's: values without
regard to case, `*` and `?` wildcards, a list is any of, `|all` all of, the
modifiers contains, startswith, endswith, re, and the condition's and, or,
not, brackets, `1 of`/`all of` a pattern or `them`."""
import fnmatch
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from events import events


def fields(e):
    if e["kind"] == "process":
        return "process_creation", {"Image": e["image"], "CommandLine": e["cmdline"], "ParentImage": e["parent_image"],
                                    "ParentCommandLine": e["parent_cmdline"], "OriginalFileName": os.path.basename(e["image"])}
    if e["kind"] == "file" and e["action"] in ("creation", "rename", "modification"):
        return "file_event", {"TargetFilename": e["path"], "Image": e["image"]}
    return None, None


def one(value, got, mods):
    if got is None:
        return value is None
    if value is None:
        return got == ""
    got, value = str(got), str(value)
    if "re" in mods:
        return re.search(value, got) is not None
    g, v = got.lower(), value.lower()
    if "contains" in mods:
        v = "*" + v + "*"
    elif "startswith" in mods:
        v = v + "*"
    elif "endswith" in mods:
        v = "*" + v
    if "*" in v or "?" in v:
        return fnmatch.fnmatchcase(g, v.replace("[", "[[]"))
    return g == v


def selection(sel, f):
    if isinstance(sel, list):
        return any(selection(s, f) for s in sel)
    if not isinstance(sel, dict):
        return any(one(sel, v, ["contains"]) for v in f.values())  # a keyword
    for k, want in sel.items():
        name, *mods = k.split("|")
        if name not in f:
            return False
        vals = want if isinstance(want, list) else [want]
        hits = [one(v, f[name], mods) for v in vals]
        if not (all(hits) if "all" in mods else any(hits)):
            return False
    return True


def condition(text, names, truth):
    toks = re.findall(r"\(|\)|[\w*]+", text)
    pos = 0

    def peek():
        return toks[pos] if pos < len(toks) else None

    def take():
        nonlocal pos
        pos += 1
        return toks[pos - 1]

    def of(quant, pat):
        pick = [n for n in names if pat == "them" or fnmatch.fnmatchcase(n, pat)]
        vals = [truth(n) for n in pick]
        return all(vals) and bool(vals) if quant == "all" else sum(vals) >= int(quant)

    def atom():
        t = take()
        if t == "(":
            v = expr()
            take()
            return v
        if t == "not":
            return not atom()
        if peek() == "of":
            take()
            return of(t, take())
        return truth(t)

    def conj():
        v = atom()
        while peek() == "and":
            take()
            w = atom()
            v = v and w
        return v

    def expr():
        v = conj()
        while peek() == "or":
            take()
            w = conj()
            v = v or w
        return v

    return expr()


def run(rules, evs):
    fired = {}
    for e in evs:
        cat, f = fields(e)
        if not cat:
            continue
        for r in rules:
            if r["logsource"].get("category") != cat:
                continue
            det = r["detection"]
            names = [k for k in det if k != "condition"]
            conds = det["condition"] if isinstance(det["condition"], list) else [det["condition"]]
            memo = {}

            def truth(n):
                if n not in memo:
                    memo[n] = selection(det[n], f)
                return memo[n]

            if any(condition(c, names, truth) for c in conds):
                hit = fired.setdefault(r["title"], {"level": r.get("level"), "file": r["_file"].split("/rules", 1)[-1], "count": 0, "first": None})
                hit["count"] += 1
                hit["first"] = hit["first"] or (f.get("CommandLine") or f.get("TargetFilename"))[:300]
    return fired


if __name__ == "__main__":
    rules = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "sigma.json")))
    out = {}
    for case in sorted(os.listdir(sys.argv[1])):
        for side in ("attack", "twin"):
            d = os.path.join(sys.argv[1], case, side)
            if os.path.exists(os.path.join(d, "es.ndjson.zst")):
                evs = events(d)
                out[f"{case}/{side}"] = {"events": len(evs), "process": sum(e["kind"] == "process" for e in evs), "fired": run(rules, evs)}
    json.dump(out, sys.stdout, indent=1)
