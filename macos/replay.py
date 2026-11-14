"""replay.py RECORDING WORK [--judge]: a recording through the macOS pack.

RECORDING is a directory record.sh wrote (es.ndjson.zst, net.ndjson). The
sensor's lines and the connections are put in one stream in time order, as the
pack's two sockets would have delivered them, and run through plugin `macos`
and plugin `macos_sessions`. No model is asked anything: this is what the
judge would be shown.

  WORK/stream.ndjson     the merged stream
  WORK/records.ndjson    what plugin `macos` keeps
  WORK/sessions.ndjson   the session summaries the judge reads

With --judge the stream goes through the pack as examples/macos runs it, one
process: the plugins, the judge on each session summary, and the second
reviewer on each alert (examples/macos/anthropic.yaml: both models on
ANTHROPIC_API_KEY, which costs money). It is stopped once every alert has
its review and nothing new has come for a while.

  WORK/verdicts.ndjson   each summary with the judge's answer
  WORK/alerts.ndjson     what the pack would tell a person of
  WORK/reviews.ndjson    each alert with the reviewer's finding

tangent comes from TANGENT_ROOT, a tangent checkout with packs/macos; its
compiled plugins from TANGENT_PLUGINS (default TANGENT_ROOT/examples/macos/plugins:
compiled from the checkout as it is now, or the run is of an older pack);
and TANGENT, a tangent you built (default TANGENT_ROOT/target/release/tangent). Needs zstd on the PATH.
"""
import json
import os
import signal
import subprocess
import sys
import time

QUIET = 180      # seconds with no new verdict, alert or review before a judged run is taken as done
LIMIT = 2400     # and the longest one may take


def plugins(root):
    return os.path.abspath(os.environ.get("TANGENT_PLUGINS") or os.path.join(root, "examples", "macos", "plugins"))


def merge(recording, out_path):
    """The sensor's lines in their order, each connection put before the
    first sensor event that is later than it."""
    with open(os.path.join(recording, "net.ndjson")) as f:
        net = sorted((json.loads(line)["time"], line) for line in f if line.strip())
    es = subprocess.Popen(["zstd", "-dc", os.path.join(recording, "es.ndjson.zst")], stdout=subprocess.PIPE, text=True)
    i = lines = 0
    with open(out_path, "w") as out:
        for line in es.stdout:
            at = line.find('"time":"')
            if at >= 0 and '"event"' in line:
                t = line[at + 8:at + 38]
                while i < len(net) and net[i][0] < t:
                    out.write(net[i][1])
                    i += 1
            out.write(line)
            lines += 1
        for _, line in net[i:]:
            out.write(line)
    if es.wait():
        sys.exit(f"zstd could not read {recording}/es.ndjson.zst")
    return lines, len(net)


def config(root, work):
    at = lambda f: os.path.join(work, f)
    sink = lambda f: {"type": "file", "path": at(f), "compression": {"type": "none"}}
    pack = os.path.join(root, "packs", "macos")
    return {
        "include": [os.path.join(pack, "ingest.yaml"), os.path.join(pack, "lake.yaml")],
        "runtime": {"plugins_path": plugins(root) + "/",
                    "state": {"path": at("plugins.sqlite")}},
        "sources": {"es": {"type": "file", "path": at("stream.ndjson"),
                           "decoding": {"format": {"type": "ndjson"}, "compression": {"type": "none"}}}},
        "sinks": {"recs": sink("records.ndjson"), "sums": sink("sessions.ndjson"),
                  # the pack's lake sink comes with its config; a judged run's reviewer reads WORK/lake, so not there
                  "lake": {"path": at("plugins-lake/logs/%Y/%m/%d/%H"), "wal_path": at("plugins-lake/wal")}},
        "dag": [{"from": "es", "to": ["macos"]},
                {"from": "macos", "to": ["recs", "lake", "macos_sessions"]},
                {"from": "macos_sessions", "to": ["sums"]}],
    }


def judged_config(root, work):
    """examples/macos with the reviewer, reading the stream from a file and
    writing here."""
    at = lambda f: os.path.join(work, f)
    return {
        "include": [os.path.join(root, "examples", "macos", "anthropic.yaml")],
        "runtime": {"plugins_path": plugins(root) + "/",
                    "state": {"path": at("judged.sqlite")}},
        "sources": {"es": {"type": "file", "path": at("stream.ndjson"), "socket_path": None,
                           "decoding": {"format": {"type": "ndjson"}, "compression": {"type": "none"}}}},
        "sinks": {"lake": {"path": at("lake/logs/%Y/%m/%d/%H"), "wal_path": at("lake/wal")},
                  "alerts": {"path": at("alerts.ndjson")}, "verdicts": {"path": at("verdicts.ndjson")},
                  "reviews": {"path": at("reviews.ndjson")}},
    }


def judged(tangent, root, work):
    if not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("--judge needs ANTHROPIC_API_KEY")
    with open(os.path.join(work, "judged.json"), "w") as f:
        json.dump(judged_config(root, work), f, indent=1)
    outs = [os.path.join(work, f) for f in ("verdicts.ndjson", "alerts.ndjson", "reviews.ndjson")]
    with open(os.path.join(work, "judged.log"), "w") as log:
        proc = subprocess.Popen([tangent, "run", "--config", "judged.json"], cwd=work, stdout=log, stderr=subprocess.STDOUT)
        started = changed = time.time()
        seen = None
        while proc.poll() is None:
            time.sleep(5)
            now = [count(p) for p in outs]
            if now != seen:
                seen, changed = now, time.time()
            reviewed = now[2] >= now[1]
            if (now[0] and reviewed and time.time() - changed > QUIET) or time.time() - started > LIMIT:
                proc.send_signal(signal.SIGTERM)
                proc.wait()
        if proc.returncode not in (0, -signal.SIGTERM):
            sys.exit(f"tangent exited {proc.returncode}: see {work}/judged.log")
    print(f"{seen[0]} verdicts, {seen[1]} alerts, {seen[2]} reviews" + ("" if seen[2] >= seen[1] else ": stopped before every alert was reviewed"))


def count(path):
    try:
        with open(path, "rb") as f:
            return sum(1 for _ in f)
    except OSError:
        return 0


def main():
    args = [a for a in sys.argv[1:] if a != "--judge"]
    if len(args) != 2:
        sys.exit(__doc__.split("\n\n")[0])
    recording, work = os.path.abspath(args[0]), os.path.abspath(args[1])
    root = os.environ.get("TANGENT_ROOT") or sys.exit("set TANGENT_ROOT to a tangent checkout")
    root = os.path.abspath(root)
    tangent = os.environ.get("TANGENT") or os.path.join(root, "target", "release", "tangent")
    if not os.path.exists(os.path.join(plugins(root), "macos_sessions.cwasm")):
        sys.exit(f"{plugins(root)} has no compiled plugins: tangent plugin compile --config tangent.yaml, in examples/macos")
    if os.path.exists(work) and os.listdir(work):
        sys.exit(f"{work} is not empty")
    os.makedirs(work, exist_ok=True)
    lines, connections = merge(recording, os.path.join(work, "stream.ndjson"))
    with open(os.path.join(work, "plugins.json"), "w") as f:
        json.dump(config(root, work), f, indent=1)
    with open(os.path.join(work, "plugins.log"), "w") as log:
        rc = subprocess.run([tangent, "run", "--config", "plugins.json", "--once"], cwd=work, stdout=log,
                            stderr=subprocess.STDOUT).returncode
    if rc:
        sys.exit(f"tangent exited {rc}: see {work}/plugins.log")
    print(f"{lines} sensor lines and {connections} connections in; "
          f"{count(os.path.join(work, 'records.ndjson'))} records kept, "
          f"{count(os.path.join(work, 'sessions.ndjson'))} session summaries")
    if "--judge" in sys.argv:
        judged(tangent, root, work)


if __name__ == "__main__":
    main()
