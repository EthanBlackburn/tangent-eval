"""page.py [RUNS_DIR]: the suite's results, and the front page's table.

Reads every judged replay under RUNS_DIR (default ../runs/macos/replay), a
directory `<case>-<attack|twin>` or `<case>-<attack|twin>-<n>` that
`replay.py --judge` wrote, and says of each case:

  attack   in how many runs the judge marked the case, and in how many an
           alert was still standing after the reviewer
  twin     the same; a twin should be left alone
  other    alerts standing on anything else in the recording (the VM's own
           background), over all the case's runs

A verdict is the case's when its session began at one of the case's `entry`
apps (case.json: the app its lines are typed into, by default Terminal, and
any app they open that the case runs in). An alert stands
unless its review says benign: a review that failed leaves it standing.

A case with no judged run is in the table as "recorded, not judged yet"
when its recording is beside RUNS_DIR (../recordings/<case>/attack), and
otherwise in the list of what is next.

Writes results.json beside this file and, between their markers in
README.md, the headline counts, the table of recorded incidents and the
list of those still to record. No model is asked anything.
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def load(path):
    try:
        with open(path) as f:
            return [json.loads(line) for line in f if line.strip()]
    except OSError:
        return []


def key(record):
    s = record.get("session") or {}
    return s.get("id"), s.get("window")


def run(path, entry):
    """One judged replay: was the case marked, does an alert on it stand, and
    how many alerts stand on anything else."""
    mine = lambda r: os.path.basename((r.get("session") or {}).get("entry") or "") in entry
    verdicts, alerts = load(os.path.join(path, "verdicts.ndjson")), load(os.path.join(path, "alerts.ndjson"))
    cleared = {key(r) for r in load(os.path.join(path, "reviews.ndjson")) if (r.get("review") or {}).get("verdict") == "benign"}
    standing = [a for a in alerts if key(a) not in cleared]
    return {
        "marked": any(mine(v) and (v.get("judge") or {}).get("warrants_investigation") in ("look", "flag") for v in verdicts),
        "stands": any(mine(a) for a in standing),
        "other": sum(1 for a in standing if not mine(a)),
    }


def results(runs_dir):
    out = {}
    for name in sorted(os.listdir(runs_dir)) if os.path.isdir(runs_dir) else []:
        m = re.fullmatch(r"(.+)-(attack|twin)(?:-\d+)?", name)
        path = os.path.join(runs_dir, name)
        if not m or not os.path.exists(os.path.join(path, "verdicts.ndjson")):
            continue
        case, what = m.groups()
        try:
            with open(os.path.join(HERE, "cases", case, "case.json")) as f:
                entry = json.load(f).get("entry", "Terminal")
                entry = [entry] if isinstance(entry, str) else entry
        except OSError:
            continue
        r = run(path, entry)
        c = out.setdefault(case, {"attack": {"runs": 0, "marked": 0, "stands": 0}, "twin": {"runs": 0, "marked": 0, "stands": 0}, "other": 0})
        c[what]["runs"] += 1
        c[what]["marked"] += r["marked"]
        c[what]["stands"] += r["stands"]
        c["other"] += r["other"]
    return out


def of(n, runs):
    return f"{n} of {runs} run{'s' if runs != 1 else ''}"


def recorded(i, res, recordings):
    r = res.get(i["id"])
    return bool(r and r["attack"]["runs"]) or os.path.isdir(os.path.join(recordings, i["id"], "attack"))


def table(incidents, res):
    """A row for each incident that has a recording."""
    rows = ["| Incident | Arrives as | What it does on the Mac | Attack caught | Look-alike left alone |", "|---|---|---|---|---|"]
    for i in incidents:
        r = res.get(i["id"])
        if r and r["attack"]["runs"]:
            caught = of(r["attack"]["stands"], r["attack"]["runs"])
            alone = of(r["twin"]["runs"] - r["twin"]["stands"], r["twin"]["runs"]) if r["twin"]["runs"] else "not run"
        else:
            caught = alone = "recorded, not judged yet"
        rows.append(f"| [{i['name']}](cases/{i['id']}) | {i['how']} | {i['does']} | {caught} | {alone} |")
    return "\n".join(rows)


def headline(res):
    """The two counts a reader takes away: attacks caught in every run, and
    look-alikes left alone in every run."""
    judged = [r for r in res.values() if r["attack"]["runs"]]
    caught = sum(1 for r in judged if r["attack"]["stands"] == r["attack"]["runs"])
    twins = [r for r in judged if r["twin"]["runs"]]
    alone = sum(1 for r in twins if r["twin"]["stands"] == 0)
    return (f"**{caught} of {len(judged)} attacks caught, in every run. "
            f"{alone} of {len(twins)} look-alikes left alone, in every run.**")


def upcoming(incidents):
    return "\n".join(f"- **{i['name']}** ({i['how']}): {i['does'][0].lower() + i['does'][1:]}" for i in incidents)


def put(text, name, body):
    begin, end = f"<!-- {name}: page.py writes this -->", f"<!-- /{name} -->"
    if begin not in text or end not in text:
        sys.exit(f"README.md has no {begin} ... {end} markers")
    head, rest = text.split(begin, 1)
    return head + begin + "\n" + body + "\n" + end + rest.split(end, 1)[1]


def main():
    runs_dir = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "runs", "macos", "replay"))
    res = results(runs_dir)
    with open(os.path.join(HERE, "results.json"), "w") as f:
        json.dump(res, f, indent=1, sort_keys=True)
        f.write("\n")
    with open(os.path.join(HERE, "incidents.json")) as f:
        incidents = json.load(f)
    recordings = os.path.join(os.path.dirname(runs_dir), "recordings")
    have = [i for i in incidents if recorded(i, res, recordings)]
    readme = os.path.join(HERE, "README.md")
    with open(readme) as f:
        text = f.read()
    text = put(text, "headline", headline(res))
    text = put(text, "results", table(have, res))
    text = put(text, "next", upcoming([i for i in incidents if i not in have]))
    with open(readme, "w") as f:
        f.write(text)
    for case, r in res.items():
        print(f"{case}: attack marked {of(r['attack']['marked'], r['attack']['runs'])}, standing {of(r['attack']['stands'], r['attack']['runs'])}; "
              f"twin marked {of(r['twin']['marked'], r['twin']['runs'])}, standing {of(r['twin']['stands'], r['twin']['runs'])}; "
              f"{r['other']} other alerts standing")


if __name__ == "__main__":
    main()
