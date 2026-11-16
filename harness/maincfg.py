#!/usr/bin/env python3
"""A WORK dir for replay.py / shard.py: tangent's packs as examples/cloud-infra
includes them (judge, which brings enrich-ip and behavior-baseline, and
cloudtrail, github, okta, google_workspace), fed by one tcp source.

    python3 -I harness/maincfg.py shipped|isolated WORK [--port N] [--judge bedrock|local]
                                  [--profile FILE] [--tripwire NAME=PATH]

examples/cloud-infra is one process whose judge takes each actor's records
as a group closed by the clock (thirty records, or an hour). A replay of
thirteen months cannot wait an hour per group, so the harness runs the same
plugins, brief and model as two processes with a queue between them, which
replay.py steps by the records' own times:

  ingest.yaml  the four packs' plugins, each record to logs.sqlite (a sqlite
               sink partitioned by actor) and to baseline_builder
  judge.yaml   a sqlite source over logs.sqlite handing baseline_renderer an
               actor's forty latest records, the new ones and, marked
               `_context`, what tops them up; then the judge pack's judge,
               fresh and flagged, as it ships

So the model reads what it reads live: one actor's records, forty at most,
`_baseline` on them, as logfmt, under packs/judge's brief. What differs is
when a group closes: here at forty pending or an hour of record time, live
at thirty new or an hour of the clock.

shipped:  baseline_builder in ingest folds every record (every case too)
          into WORK/state.sqlite; the judge reads it read-only. An earlier
          case's calls, addresses and resources are then "seen" for a later
          case.
isolated: no baseline_builder in ingest; history.yaml (the learn config
          replay.py runs per window) folds the ordinary stream plus only that
          window's cases into state.window.sqlite, which the judge reads. No
          case reads another case's history.

--judge bedrock (the default): Claude Haiku 5.5 on Bedrock: thinking disabled,
          max_tokens 400, no temperature or top_p (Haiku 5.5 refuses them),
          concurrency 16, retries 6. BEDROCK_MODEL overrides the model,
          BEDROCK_REGION the region (us-west-2); AWS_PROFILE, when set, is the
          profile written into judge.yaml (else the default credential chain).
--judge local: packs/judge's model as it ships, any OpenAI-compatible server
          at JUDGE_URL (http://localhost:8080/v1 by default), JUDGE_MODEL,
          with one request in flight: one model on one machine is no faster
          with more.
--tripwire NAME=PATH: a plugin NAME at PATH after every pack plugin (beside
          `logs`), writing to WORK/tripwire.ndjson; left out of history.yaml.

The configs include the packs' own files, so tangent merges them, and are
written as JSON, which YAML holds: nothing here or in replay.py parses YAML.
Their plugins are compiled into WORK/plugins by the tangent that runs them:

    $TANGENT plugin compile --config WORK/ingest.yaml && $TANGENT plugin compile --config WORK/judge.yaml

It also writes judge-sim.yaml: the judge's groups with `_baseline` stamped and
written to WORK/headers.ndjson, no model (JUDGE=judge-sim.yaml replay.py ...)."""
import argparse
import copy
import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.environ.get("TANGENT_ROOT") or os.path.join(HERE, "..", "tangent"))  # the tangent repository (Makefile)
PACKS = ["cloudtrail", "github", "okta", "google_workspace"]  # examples/cloud-infra's

ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
ap.add_argument("arm", choices=["shipped", "isolated"])
ap.add_argument("work")
ap.add_argument("--port", type=int, default=9501)
ap.add_argument("--judge", choices=["bedrock", "local"], default="bedrock")
ap.add_argument("--profile", default=os.path.join(HERE, "..", "profile", "profile.yaml"))
ap.add_argument("--tripwire", metavar="NAME=PATH")
args = ap.parse_args()
arm, port = args.arm, args.port
work, profile = os.path.abspath(args.work), os.path.abspath(args.profile)
trip = args.tripwire.split("=", 1) if args.tripwire else None
os.makedirs(work, exist_ok=True)
at = lambda f: os.path.join(work, f)
pack = lambda name, f="ingest.yaml": os.path.join(ROOT, "packs", name, f)


def put(f, c):
    with open(at(f), "w") as out:
        json.dump(c, out, indent=1)
        out.write("\n")


def state(path, **more):
    return {"backend": "sqlite", "path": at(path), "default_ttl_ms": 0, "max_ttl_ms": 0, **more}


shutil.copyfile(profile, at("profile.yaml"))
tables = {"profile": {"type": "document", "path": at("profile.yaml"), "required": True}}
plain = {"type": "none"}

# ---- ingest: every record to the judge's queue, and into its actor's history
i = {
    "include": [pack("enrich-ip"), pack("behavior-baseline")] + [pack(p) for p in PACKS],
    "runtime": {"workers": 1, "plugins_path": at("plugins"), "state": state("state.sqlite")},
    "enrichment_tables": tables,
    "sources": {"events": {"type": "tcp", "bind_address": f"127.0.0.1:{port}"}},
    "sinks": {"logs": {"type": "sqlite", "path": at("logs.sqlite"), "table": "logs", "timestamp_key": "ts",
                       "partitions": {"org": ["_norm.org"], "actor": ["_norm.org", "_norm.actor"]}}},
    "dag": [{"from": "events", "to": PACKS}] + [{"from": p, "to": ["logs", "baseline_builder"]} for p in PACKS],
}
learn = copy.deepcopy(i)
if arm == "isolated":
    for e in i["dag"][1:]:
        e["to"].remove("baseline_builder")
if trip:
    name, path = trip
    i["plugins"] = {name: {"module_type": "rust", "path": os.path.abspath(path)}}
    i["sinks"]["tripwire"] = {"type": "file", "path": at("tripwire.ndjson"), "compression": plain}
    for e in i["dag"][1:]:
        e["to"].append(name)
    i["dag"].append({"from": name, "to": ["tripwire"]})
put("ingest.yaml", i)

# ---- history.yaml: the learn config replay.py runs per window (isolated only)
if arm == "isolated":
    h = learn
    h["runtime"]["state"] = state("state.window.sqlite")
    h["sources"] = {"learn": {"type": "file", "path": at("learn.ndjson"),
                              "decoding": {"format": {"type": "ndjson"}, "compression": plain}}}
    h["sinks"] = {"none": {"type": "blackhole"}}  # a config wants a sink
    h["dag"] = [{"from": "learn", "to": PACKS}] + [{"from": p, "to": ["baseline_builder", "none"]} for p in PACKS]
    put("history.yaml", h)

# ---- judge: the queue's batches in place of the renderer's groups
shutil.copyfile(pack("judge", "judge.md"), at("judge.md"))
ungrouped = {"group_by": None, "max_events": None, "max_age_ms": None, "expire_after_ms": None, "history": None}
j = {
    "include": [pack("judge")],
    "runtime": {"workers": 1, "plugins_path": at("plugins"), "batch_size": 4096, "batch_age": 200,
                "state": state("state.window.sqlite" if arm == "isolated" else "state.sqlite", read_only=True)},
    "enrichment_tables": tables,
    "sources": {"actors": {"type": "sqlite", "path": at("logs.sqlite"), "table": "logs", "partition": "actor",
                           "batch_size": 40, "timeout_secs": 3600}},
    "plugins": {"baseline_renderer": ungrouped},
    "inference": {"judge": {"prompt_file": at("judge.md")}},
    "sinks": {"alerts": {"path": at("alerts.ndjson")}, "verdicts": {"path": at("verdicts.ndjson")},
              "seen": {"type": "file", "path": at("seen.ndjson"), "compression": plain}},  # every record the model read, for cost
    "dag": [{"from": "actors", "to": ["baseline_renderer"]}, {"from": "judge", "to": ["seen"]}],
}
m = j["inference"]["judge"]
if args.judge == "bedrock":
    aws = {"region": os.environ.get("BEDROCK_REGION") or "us-west-2"}
    if os.environ.get("AWS_PROFILE"):
        aws["profile"] = os.environ["AWS_PROFILE"]
    j["include"] = [pack("judge", "hosted.yaml")]  # the judge pack without the local model's sampling settings
    m.update(backend="bedrock", model=os.environ.get("BEDROCK_MODEL") or "us.anthropic.claude-haiku-5-5", aws=aws,
             url=None, api_key=None, max_tokens=400, timeout_ms=90000, retries=6, concurrency=16,
             extra={"thinking": {"type": "disabled"}})
    if os.environ.get("THINKING"):  # THINKING=low: it thinks before the verdict, as examples/macos/haiku.yaml has it
        m.update(max_tokens=1000, extra={"thinking": {"type": "adaptive"}, "output_config": {"effort": os.environ["THINKING"]}})
else:
    m.update(concurrency=1)
put("judge.yaml", j)

# judge-sim: the same batches with `_baseline` stamped and written down, no model
# (JUDGE=judge-sim.yaml replay.py ...: WORK/headers.ndjson, free)
sim = {
    "include": [pack("enrich-ip"), pack("behavior-baseline")],
    "runtime": j["runtime"],
    "enrichment_tables": tables,
    "sources": j["sources"],
    "sinks": {"headers": {"type": "file", "path": at("headers.ndjson"), "compression": plain}},
    "dag": [{"from": "actors", "to": ["baseline_renderer"]}, {"from": "baseline_renderer", "to": ["headers"]}],
}
put("judge-sim.yaml", sim)
print(f"{work}: {arm}, judge {args.judge}; tangent's packs from {ROOT}", file=sys.stderr)
