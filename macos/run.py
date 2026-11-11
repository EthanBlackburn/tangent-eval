#!/usr/bin/env python3
"""Replay a stream through tangent's macOS pack, and judge what it sums up.

    python3 -I macos/run.py STREAM WORK [--judge none|bedrock|local] [--workers N]

Two tangent runs, their configs written into WORK (as JSON, which is YAML):

1. WORK/plugins.json: packs/macos/ingest.yaml with a file source reading
   STREAM (gzipped when its name ends in .gz) and two file sinks:
   WORK/records.ndjson, what plugin `macos` keeps of the events, and
   WORK/sessions.ndjson, `macos_sessions`' summaries, one per session and
   window, which is what the judge reads. `tangent run --once`; free.
2. With --judge bedrock or local, WORK/judge.json: examples/macos as shipped
   (haiku.yaml for bedrock: Claude Haiku 5.5, signed in as AWS_PROFILE;
   tangent.yaml for local: JUDGE_URL and JUDGE_MODEL), with the summaries as
   a file source routed to the judge, on N workers (default 8). tangent runs
   until every summary has its verdict and is then stopped (`--once` gives
   up on the requests still out when the file ends); a run with no new
   verdict for ten minutes is stopped too, and says so.
   WORK/verdicts.ndjson is each summary with its `judge`, and
   WORK/alerts.ndjson what the pack would tell a person of. A judged run
   costs money (Bedrock: about a dollar for the default stream) or a local
   model's hours.

Two runs because the pack runs on one worker (the plugin builds the process
tree from fork, exec and exit, in order) and the worker count is the whole
pipeline's: in one process the judge would take one summary at a time. The
price is that the judge here never gets `so_far`, its own running summary of
a session's earlier windows, which the pack carries when it runs live.

tangent comes from TANGENT_ROOT, a checkout of the tangent repository that
has packs/macos (default: tangent/ beside this directory, as the Makefile's),
and TANGENT, a tangent you built (default: TANGENT_ROOT/target/release/tangent).
The pack's plugins are compiled into TANGENT_ROOT/examples/macos/plugins
when they are missing. score.py reads WORK."""
import argparse
import json
import os
import signal
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.environ.get("TANGENT_ROOT") or os.path.join(HERE, "..", "tangent"))
PACK = os.path.join(ROOT, "packs", "macos")
EX = os.path.join(ROOT, "examples", "macos")
TANGENT = os.environ.get("TANGENT") or os.path.join(ROOT, "target", "release", "tangent")
STALL = 600  # seconds with no new verdict before a judged run is given up on


def file_source(path):
    return {"type": "file", "path": path,
            "decoding": {"format": {"type": "ndjson"}, "compression": {"type": "gzip" if path.endswith(".gz") else "none"}}}


def file_sink(path):
    return {"type": "file", "path": path, "compression": {"type": "none"}}


def plugins_config(stream, at):
    return {
        "include": [os.path.join(PACK, "ingest.yaml")],
        "runtime": {"plugins_path": os.path.join(EX, "plugins") + "/", "state": {"path": at("plugins.sqlite")}},
        "sources": {"es": file_source(stream)},
        "sinks": {"recs": file_sink(at("records.ndjson")), "sums": file_sink(at("sessions.ndjson"))},
        "dag": [{"from": "es", "to": ["macos"]},
                {"from": "macos", "to": ["recs", "macos_sessions"]},
                {"from": "macos_sessions", "to": ["sums"]}],
    }


def judge_config(which, workers, at):
    # The example's own sources are sockets: `es` becomes a file of one empty
    # record, which the router drops, and `net` stays a socket nobody writes.
    quiet = dict(file_source(at("none.ndjson")), socket_path=None)
    return {
        "include": [os.path.join(EX, "haiku.yaml" if which == "bedrock" else "tangent.yaml")],
        "runtime": {"workers": workers, "plugins_path": os.path.join(EX, "plugins") + "/",
                    "state": {"path": at("judge.sqlite")}},
        "inference": {"judge": {"retries": 10}},
        "sources": {"es": quiet, "sums": file_source(at("sessions.ndjson"))},
        "sinks": {"lake": {"path": at("lake/logs/%Y/%m/%d/%H"), "wal_path": at("lake/wal")},
                  "alerts": {"path": at("alerts.ndjson")},
                  "verdicts": {"path": at("verdicts.ndjson")}},
        "dag": [{"from": "sums", "to": ["judge"]}],
    }


def tangent(args, work, log):
    with open(os.path.join(work, log), "w") as out:
        rc = subprocess.run([TANGENT] + args, cwd=work, stdout=out, stderr=subprocess.STDOUT).returncode
    if rc:
        sys.exit(f"tangent {' '.join(args[:2])} exited {rc}: see {os.path.join(work, log)}")


def count(path):
    try:
        with open(path, "rb") as f:
            return sum(1 for _ in f)
    except OSError:
        return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("stream")
    ap.add_argument("work")
    ap.add_argument("--judge", choices=["none", "bedrock", "local"], default="none")
    ap.add_argument("--workers", type=int, default=8)
    a = ap.parse_args()
    stream, work = os.path.abspath(a.stream), os.path.abspath(a.work)
    at = lambda f: os.path.join(work, f)
    for need, why in ((stream, "no such stream"), (PACK, "TANGENT_ROOT has no packs/macos"), (TANGENT, "no tangent built: TANGENT")):
        if not os.path.exists(need):
            sys.exit(f"{need}: {why}")
    os.makedirs(work, exist_ok=True)

    if not os.path.exists(os.path.join(EX, "plugins", "macos_sessions.cwasm")):
        print("compiling the pack's plugins")
        tangent(["plugin", "compile", "--config", os.path.join(EX, "tangent.yaml")], EX, at("compile.log"))

    if not count(at("sessions.ndjson")):
        for f in ("records.ndjson", "sessions.ndjson", "plugins.sqlite"):
            if os.path.exists(at(f)):
                os.remove(at(f))
        with open(at("plugins.json"), "w") as f:
            json.dump(plugins_config(stream, at), f, indent=1)
        tangent(["run", "--once", "--config", at("plugins.json")], work, "plugins.log")
    sessions = count(at("sessions.ndjson"))
    print(f"{count(at('records.ndjson'))} records kept, {sessions} session summaries")
    if not sessions:
        sys.exit(f"no summaries: see {at('plugins.log')}")
    if a.judge == "none":
        return

    if count(at("verdicts.ndjson")):
        sys.exit(f"{at('verdicts.ndjson')} exists: a judged run needs a WORK of its own, or remove it")
    with open(at("none.ndjson"), "w") as f:
        f.write("{}\n")
    with open(at("judge.json"), "w") as f:
        json.dump(judge_config(a.judge, a.workers, at), f, indent=1)
    with open(at("judge.log"), "w") as log:
        p = subprocess.Popen([TANGENT, "run", "--config", at("judge.json")], cwd=work, stdout=log, stderr=subprocess.STDOUT)
    seen, since = 0, time.time()
    while p.poll() is None and seen < sessions and time.time() - since < STALL:
        time.sleep(5)
        now = count(at("verdicts.ndjson"))
        if now != seen:
            seen, since = now, time.time()
    if p.poll() is None:
        time.sleep(3)  # the sinks' last lines
        p.send_signal(signal.SIGTERM)
        p.wait()
    verdicts = count(at("verdicts.ndjson"))
    print(f"{verdicts} verdicts, {count(at('alerts.ndjson'))} alerts")
    if verdicts != sessions:
        sys.exit(f"{sessions - verdicts} summaries have no verdict: see {at('judge.log')}")


if __name__ == "__main__":
    main()
