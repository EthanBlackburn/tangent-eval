"""The cloud corpus tangent's runs are scored on, for a ruleset to be scored the same way.

    stream(path)                      -> the records, in order
    write(run, stream, hits, out)     -> out/verdicts.ndjson: the run's judged records, `judge.flag` true
                                         where a rule fired (hits: record number -> rule names)

`run` is a tangent run's verdicts.ndjson: the same records are scored, so the
ordinary count and the cases are the ones tangent's numbers are over. A
ruleset reads the whole stream (a rule that asks what is new needs the
history); only the verdicts are cut to the run's records."""
import json
import os

ADDED = ("_baseline", "_facts", "_norm", "judge", "_context")


def scalars(r):
    return {k: v for k, v in r.items() if k not in ADDED and not isinstance(v, (dict, list))}


def stream(path):
    return [json.loads(l) for l in open(path)]


def write(run, records, hits, out):
    os.makedirs(out, exist_ok=True)
    by = {}  # the packs trim a record before it is judged: a judged record is the stream's whose plain fields it keeps
    for i, r in enumerate(records):
        by.setdefault((r["ts"], r["source"]), []).append(i)
    n = missing = 0
    with open(os.path.join(out, "verdicts.ndjson"), "w") as f:
        for line in open(run):
            r = json.loads(line)
            mine = scalars(r).items()
            idx = [i for i in by.get((r["ts"], r["source"]), []) if mine <= records[i].items()]
            missing += not idx
            rules = sorted({name for i in idx for name in hits.get(i, ())})
            r["judge"] = {"flag": bool(rules), "rules": rules}
            f.write(json.dumps(r) + "\n")
            n += 1
    return n, missing
