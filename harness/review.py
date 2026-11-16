#!/usr/bin/env python3
"""The second reviewer over a judged run's alerts: packs/judge's plugin `review`
(review.yaml: a stronger model that queries the lake) settles each actor's
alerts, window by window, and the run is scored again with what it called
benign no longer flagged.

    TANGENT=... TRUTH=... python3 -I harness/review.py RUN STREAM WINDOWS OUT [--jobs N] [--only K,K]

RUN is a finished run (its alerts.ndjson and verdicts.ndjson). For each window
with alerts, in a directory of its own under OUT:

  lake.yaml    the window's records through the packs into a Parquet lake, as
               examples/cloud-infra keeps one: the ordinary stream for DAYS (30)
               up to the window's end, and the rows of the cases the window
               touches. No case's rows are in another window's lake, as no
               case is in another's history (replay.py, isolated).
  review.yaml  the window's alerts through plugin review, an actor's together,
               to reviews.ndjson.

OUT/reviews.ndjson is every alert with its review, and OUT/verdicts.ndjson the
run's verdicts with `judge.flag` false where the review said benign
(`judge.reviewed: benign`), which score_v2.py reads as any run's.

TANGENT_ROOT is the tangent checkout whose packs the lake is made with and
REVIEW_ROOT the one with packs/judge/review.yaml (TANGENT_ROOT unless set).
AWS_PROFILE, when set, is the profile the reviewer signs in with. REVIEW_URL
names an OpenAI-compatible server in Bedrock's place: a stand-in, to check the
harness without a model, or with REVIEW_MODEL and REVIEW_API_KEY a hosted one. Standard library only."""
import argparse
import bisect
import json
import os
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.environ.get("TANGENT_ROOT") or os.path.join(HERE, "..", "tangent"))
REVIEW = os.path.abspath(os.environ.get("REVIEW_ROOT") or ROOT)
T = os.environ.get("TANGENT") or sys.exit("TANGENT: set it to the tangent binary")
TRUTH = os.environ.get("TRUTH") or sys.exit("TRUTH: the truth file, for the cases' rows")
PACKS = ["cloudtrail", "github", "okta", "google_workspace"]
DAYS = int(os.environ.get("DAYS", "30"))

ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
ap.add_argument("run")
ap.add_argument("stream")
ap.add_argument("windows")
ap.add_argument("out")
ap.add_argument("--jobs", type=int, default=4)
ap.add_argument("--only", help="these windows only, by number from 1")
ap.add_argument("--profile", default=os.path.join(HERE, "..", "profile", "profile.yaml"))
args = ap.parse_args()
run, out = os.path.abspath(args.run), os.path.abspath(args.out)
os.makedirs(out, exist_ok=True)
pack = lambda name, f="ingest.yaml": os.path.join(ROOT, "packs", name, f)


def ms(s):
    return int(datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() * 1000)


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, file=sys.stderr, flush=True)


def key(r):
    """A record as score_v2.py tells it from another."""
    return (r.get("ts"), r.get("eventID") or r.get("uuid")
            or json.dumps({k: v for k, v in r.items() if k not in ("judge", "review", "reviewed")}, sort_keys=True))


cases = json.load(open(TRUTH))
case_rows = {i for c in cases for i, *_ in c["rows"]}
case_lines, rest = {}, []
with open(args.stream, "rb") as f:
    for i, line in enumerate(f):
        if i in case_rows:
            case_lines[i] = line
        else:
            rest.append(line)
rest_at = [ms(json.loads(l)["ts"]) for l in rest]
merged = []
for a, b in sorted([ms(a), ms(b)] for a, b in json.load(open(args.windows))):
    if merged and a <= merged[-1][1]:
        merged[-1][1] = max(merged[-1][1], b)
    else:
        merged.append([a, b])
alerts = [json.loads(l) for l in open(os.path.join(run, "alerts.ndjson"))]
alerts = list({key(r): r for r in alerts}.values())
only = {int(k) for k in args.only.split(",")} if args.only else None

shutil.copyfile(os.path.abspath(args.profile), os.path.join(out, "profile.yaml"))
shutil.copyfile(os.path.join(REVIEW, "packs", "judge", "review.md"), os.path.join(out, "review.md"))
plain = {"type": "none"}


def configs(w):
    at = lambda f: os.path.join(w, f)
    runtime = {"workers": 1, "plugins_path": os.path.join(out, "plugins"),
               "state": {"backend": "sqlite", "path": at("state.sqlite"), "default_ttl_ms": 0, "max_ttl_ms": 0}}
    tables = {"profile": {"type": "document", "path": os.path.join(out, "profile.yaml"), "required": True}}
    lake = {"type": "rolling_file", "path": at("lake/logs/%Y/%m/%d"), "wal_path": at("lake/wal"),
            "max_file_age_seconds": 3600, "compression": {"type": "zstd", "level": 3},
            "encoding": {"type": "parquet", "record_column": "record",  # examples/cloud-infra's, a directory a day
                         "schema": {"ts": "timestamp", "source": "string",
                                    "_norm": {"org": "string", "actor": "string", "kind": "string", "ip": "string"}}}}
    json.dump({
        "include": [pack("enrich-ip")] + [pack(p) for p in PACKS],
        "runtime": runtime, "enrichment_tables": tables,
        "sources": {"learn": {"type": "file", "path": at("learn.ndjson"),
                              "decoding": {"format": {"type": "ndjson"}, "compression": plain}}},
        "sinks": {"lake": lake},
        "dag": [{"from": "learn", "to": PACKS}] + [{"from": p, "to": ["lake"]} for p in PACKS],
    }, open(at("lake.yaml"), "w"), indent=1)
    m = {"prompt_file": os.path.join(out, "review.md")}
    if os.environ.get("REVIEW_URL"):
        # REVIEW_MODEL with it: a hosted model there, REVIEW_API_KEY its key (tangent reads it; it is not written down)
        m.update(backend=None, aws=None, url=os.environ["REVIEW_URL"], model=os.environ.get("REVIEW_MODEL") or "stand-in",
                 api_key="${REVIEW_API_KEY:-none}")
        if not os.environ.get("REVIEW_MODEL"):
            m["extra"] = None
    elif os.environ.get("AWS_PROFILE"):
        m["aws"] = {"region": os.environ.get("BEDROCK_REGION") or "us-west-2", "profile": os.environ["AWS_PROFILE"]}
    json.dump({
        "include": [os.path.join(REVIEW, "packs", "judge", "review.yaml")],
        "runtime": runtime,
        "sources": {"alerts": {"type": "file", "path": at("alerts.ndjson"),
                               "decoding": {"format": {"type": "ndjson"}, "compression": plain}}},
        "sinks": {"lake": lake, "reviews": {"type": "file", "path": at("reviews.ndjson"), "compression": plain}},
        "plugins": {"review": {"expire_after_ms": 3000}},  # the file is read at once: an actor's alerts are together by then
        "inference": {"reviewer": m},
        "dag": [{"from": "alerts", "to": ["review"]}, {"from": "review", "to": ["reviews"]}],
    }, open(at("review.yaml"), "w"), indent=1)


env = dict(os.environ, RUST_LOG=os.environ.get("RUST_LOG", "info"))
if os.environ.get("AWS_PROFILE"):
    env.pop("AWS_BEARER_TOKEN_BEDROCK", None)


def tangent(w, *a):
    with open(os.path.join(w, "tangent.log"), "ab") as logf:
        return subprocess.run([T, *a], cwd=w, env=env, stdout=logf, stderr=subprocess.STDOUT).returncode


def window(k):
    a, b = merged[k]
    mine = [r for r in alerts if a <= ms(r["ts"]) <= b]
    w = os.path.join(out, f"w{k + 1:03}")
    if not mine or os.path.exists(os.path.join(w, "done")):
        return k, len(mine)
    shutil.rmtree(w, ignore_errors=True)
    os.makedirs(w)
    configs(w)
    lo, hi = bisect.bisect_left(rest_at, b - DAYS * 86400000), bisect.bisect_right(rest_at, b)
    touched = [c for c in cases if any(a <= ms(t) <= b for t in c["times"])]
    with open(os.path.join(w, "learn.ndjson"), "wb") as f:
        f.writelines(rest[lo:hi])
        f.writelines(case_lines[i] for c in touched for i, t, *_ in c["rows"] if ms(t) <= b)
    with open(os.path.join(w, "alerts.ndjson"), "w") as f:
        for r in sorted(mine, key=lambda r: r["ts"]):
            f.write(json.dumps(r) + "\n")
    if tangent(w, "run", "--once", "--config", "lake.yaml"):
        sys.exit(f"{w}: lake.yaml failed; see tangent.log")
    if tangent(w, "run", "--once", "--config", "review.yaml"):
        sys.exit(f"{w}: review.yaml failed; see tangent.log")
    got = sum(1 for _ in open(os.path.join(w, "reviews.ndjson"))) if os.path.exists(os.path.join(w, "reviews.ndjson")) else 0
    if got != len(mine):
        log(f"window {k + 1}: {got} of {len(mine)} alerts came back; see {w}/tangent.log")
    else:
        open(os.path.join(w, "done"), "w").close()
    log(f"window {k + 1}/{len(merged)}: {len(mine)} alerts, {hi - lo} ordinary records and {len(touched)} cases in the lake")
    return k, len(mine)


todo = [k for k in range(len(merged)) if not only or k + 1 in only]
# the plugins, compiled once by the tangent that runs them
first = os.path.join(out, "compile")
os.makedirs(first, exist_ok=True)
configs(first)
open(os.path.join(first, "learn.ndjson"), "w").close()
open(os.path.join(first, "alerts.ndjson"), "w").close()
if tangent(first, "plugin", "compile", "--config", "lake.yaml") or tangent(first, "plugin", "compile", "--config", "review.yaml"):
    sys.exit(f"compiling the plugins failed; see {first}/tangent.log")
with ThreadPoolExecutor(args.jobs) as pool:
    list(pool.map(window, todo))

reviews = {}
with open(os.path.join(out, "reviews.ndjson"), "w") as f:
    for k in range(len(merged)):
        p = os.path.join(out, f"w{k + 1:03}", "reviews.ndjson")
        if os.path.exists(p):
            for line in open(p):
                f.write(line)
                r = json.loads(line)
                reviews[key(r)] = r.get("review") or {}
tally = {}
for v in reviews.values():
    x = v.get("verdict") or "error"
    tally[x] = tally.get(x, 0) + 1
with open(os.path.join(run, "verdicts.ndjson")) as src, open(os.path.join(out, "verdicts.ndjson"), "w") as f:
    for line in src:
        r = json.loads(line)
        if (r.get("judge") or {}).get("flag") is True and (reviews.get(key(r)) or {}).get("verdict") == "benign":
            r["judge"]["flag"] = False
            r["judge"]["reviewed"] = "benign"
        f.write(json.dumps(r) + "\n")
log(f"{len(alerts)} alerts, {len(reviews)} reviewed: {tally}")
