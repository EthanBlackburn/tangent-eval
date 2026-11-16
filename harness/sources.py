#!/usr/bin/env python3
"""The stream and its truth cut down to the sources tangent's packs read.

    python3 -I harness/sources.py STREAM TRUTH OUT_STREAM OUT_TRUTH

acme's stream also holds its product's own log (`app`) and its AI agent's
(`agent`). No pack reads those: a product's logs want a plugin of its own. A
record of another source is left out; a case keeps the rows that are left,
and a case with none is left out and named on stderr, as is a case that lost
some."""
import json
import sys

SOURCES = {"cloudtrail", "github_audit", "gha_ci", "runner_egress", "okta", "google_workspace"}  # maincfg.py's packs

stream, truth, out_stream, out_truth = sys.argv[1:5]
at = {}  # a kept line's number in STREAM -> its number in OUT_STREAM
left = {}
with open(stream, "rb") as f, open(out_stream, "wb") as out:
    for i, line in enumerate(f):
        s = json.loads(line).get("source")
        if s in SOURCES:
            at[i] = len(at)
            out.write(line if line.endswith(b"\n") else line + b"\n")
        else:
            left[s] = left.get(s, 0) + 1
cases, gone, cut = [], [], []
for c in json.load(open(truth)):
    rows = [[at[i], *rest] for i, *rest in c["rows"] if i in at]
    if not rows:
        gone.append(c["id"])
        continue
    if len(rows) < len(c["rows"]):
        cut.append(f"{c['id']} ({len(rows)} of {len(c['rows'])} records)")
        c = dict(c, rows=rows, times=sorted(t for _, t, *_ in rows), events=len(rows))
    else:
        c = dict(c, rows=rows)
    cases.append(c)
json.dump(cases, open(out_truth, "w"))
print(f"{len(at)} records kept; left out: " + ", ".join(f"{n} {s}" for s, n in sorted(left.items(), key=str)), file=sys.stderr)
print(f"{len(cases)} cases kept, {sum(c['flag'] for c in cases)} to flag", file=sys.stderr)
print(f"{len(gone)} cases with no record left: " + ", ".join(gone), file=sys.stderr)
print(f"{len(cut)} cases with fewer: " + ", ".join(cut), file=sys.stderr)
