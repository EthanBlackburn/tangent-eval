"""The corpus moved 104 weeks back, so the sqlite sink (which takes no time
from the future) keeps its times; weekdays and hours stay as they were.
A date inside a value moves with them (daily/20260920.json, prod-db-2026-10-20),
so a record does not name a day two years after its own.
    python3 -I evals/harness/past.py      # evals/runs/stream/{stream,truth}.* -> {stream,truth}-past.*
    python3 -I evals/harness/past.py v3   # evals/runs/stream/{stream,truth}-v3.* -> {stream,truth}-past-v3.*"""
import json, os, re, sys
from datetime import datetime, timedelta

H = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "runs", "stream")
SHIFT = timedelta(weeks=104)
ISO = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?")
# the corpus's years only: a policy's "Version": "2012-10-17" is not a day in it
DAY = re.compile(r"(?<![0-9A-Za-z])(202[5-9])(-?)(0[1-9]|1[0-2])\2([0-3]\d)(?![0-9A-Za-z:T-])")
V = "".join("-" + v for v in sys.argv[1:2])


def back(m):
    t = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S") - SHIFT
    return t.strftime("%Y-%m-%dT%H:%M:%S") + (m.group(2) or "") + (m.group(3) or "")


def day(m):
    try:
        t = datetime(int(m.group(1)), int(m.group(3)), int(m.group(4))) - SHIFT
    except ValueError:
        return m.group(0)
    return t.strftime(f"%Y{m.group(2)}%m{m.group(2)}%d")


def past(s):
    return DAY.sub(day, ISO.sub(back, s))


with open(os.path.join(H, f"stream{V}.ndjson")) as f, open(os.path.join(H, f"stream-past{V}.ndjson"), "w") as out:
    for line in f:
        out.write(past(line))
truth = json.load(open(os.path.join(H, f"truth{V}.json")))
json.dump(json.loads(past(json.dumps(truth))), open(os.path.join(H, f"truth-past{V}.json"), "w"))
