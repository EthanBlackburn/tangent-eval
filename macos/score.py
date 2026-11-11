#!/usr/bin/env python3
"""Score a run of tangent's macOS pack against the truth gen.py wrote.

    python3 -I macos/score.py TRUTH WORK

WORK is run.py's. A record is a case's when its `ts` is one of the case's
event times (the plugin writes eslogger's `time` as `ts`, and times are
unique in a stream). A session summary holds the records of its session and
window, so it is a case's when one of them is, and background when none is.

Prints: events' records kept and summaries made; per group, the cases whose
key events all came through the plugin, and the key events kept of all; and
each case with a key event missing. With verdicts, at each of the two alert
settings (`flag` alone, and `flag` or `look`): the must-flag cases caught (a
summary holding one of the case's key events got that answer), the
must-not-flag cases marked (a summary holding any of the case's events did),
the background summaries marked, and the summaries the judge could not
answer. Writes WORK/score.txt and WORK/cases.tsv (each case's loudest
answer)."""
import collections
import json
import os
import sys

LOUD = {"flag": 2, "look": 1, "pass": 0}


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    truth, work = json.load(open(sys.argv[1])), sys.argv[2]
    at = lambda f: os.path.join(work, f)
    cases = truth["cases"]

    held = collections.defaultdict(set)  # (session id, window) -> its records' times
    kept = set()
    for line in open(at("records.ndjson")):
        r = json.loads(line)
        s = r.get("session") or {}
        held[(s.get("id"), s.get("window"))].add(r.get("ts"))
        kept.add(r.get("ts"))
    of = lambda rec: held[((rec.get("session") or {}).get("id"), (rec.get("session") or {}).get("window"))]
    summaries = sum(1 for _ in open(at("sessions.ndjson")))

    out = [f"{len(kept)} records kept, {summaries} session summaries", "", "key events through the plugin",
           f"  {'group':<16}{'cases whole':>12}  key events kept"]
    groups = collections.defaultdict(lambda: [0, 0, 0, 0])
    missing = []
    for c in cases:
        keys = [k["time"] for k in c["keys"]]
        got = sum(k in kept for k in keys)
        for g in (c["group"], "all"):
            groups[g][0] += got == len(keys)
            groups[g][1] += 1
            groups[g][2] += got
            groups[g][3] += len(keys)
        if got < len(keys):
            missing.append(f"  {c['id']}: {len(keys) - got} of {len(keys)} missing: "
                           + ", ".join(sorted({f"{k['event']} {k['path']}" for k in c["keys"] if k["time"] not in kept})[:4]))
    for g in sorted(g for g in groups if g != "all") + ["all"]:
        whole, n, got, total = groups[g]
        out.append(f"  {g:<16}{f'{whole} of {n}':>12}  {got} of {total}")
    if missing:
        out += ["", "cases with a key event the plugin dropped"] + missing

    answers = {}  # case id -> its loudest answer
    if os.path.exists(at("verdicts.ndjson")):
        all_times = set().union(*(set(c["times"]) for c in cases))
        verdicts, errors, background = [], 0, collections.Counter()
        for line in open(at("verdicts.ndjson")):
            v = json.loads(line)
            j = v.get("judge") or {}
            errors += "error" in j
            answer = j.get("warrants_investigation")
            times = of(v)
            verdicts.append((times, answer))
            if not times & all_times:
                background[answer if answer in LOUD else "error"] += 1
        for c in cases:
            # an attack is caught on what shows it; a look-alike is marked on anything of its own
            mine = {k["time"] for k in c["keys"]} if c["flag"] else set(c["times"])
            got = [a for times, a in verdicts if times & mine and a in LOUD]
            answers[c["id"]] = max(got, key=LOUD.get) if got else "none"
        must = [c for c in cases if c["flag"]]
        mustnt = [c for c in cases if not c["flag"]]
        total = sum(background.values())
        out += ["", f"{len(verdicts)} verdicts, {errors} the judge could not answer"]
        for name, floor in (("flag", 2), ("flag or look", 1)):
            hit = lambda cs: sum(LOUD.get(answers[c["id"]], -1) >= floor for c in cs)
            marked = sum(n for a, n in background.items() if LOUD.get(a, -1) >= floor)
            out.append(f"  alert on {name}: {hit(must)} of {len(must)} must-flag cases caught, "
                       f"{hit(mustnt)} of {len(mustnt)} must-not-flag cases marked, "
                       f"{marked} of {total} background summaries ({100 * marked / max(total, 1):.1f}%)")
        quiet = [c["id"] for c in must if LOUD.get(answers[c["id"]], -1) < 1]
        if quiet:
            out += ["", "must-flag cases passed"] + [f"  {i}" for i in quiet]

    text = "\n".join(out) + "\n"
    sys.stdout.write(text)
    with open(at("score.txt"), "w") as f:
        f.write(text)
    with open(at("cases.tsv"), "w") as f:
        f.write("id\tgroup\tmust_flag\tanswer\n")
        for c in cases:
            f.write(f"{c['id']}\t{c['group']}\t{c['flag']}\t{answers.get(c['id'], '')}\n")


if __name__ == "__main__":
    main()
