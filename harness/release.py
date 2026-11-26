"""release.py STREAM WINDOWS WORK: the corpus through tangent as it ships.

WORK gets the pipeline `tangent init cloud --sources ...` writes, and the
stream is played into it in time order. A record inside one of WINDOWS goes
the whole way: learned, kept, judged, and reviewed if flagged. A record
outside them is history: learned and kept, never judged. Both models cost
money.

  WORK/tangent.yaml      the pipeline, as init wrote it but for what is below
  WORK/verdicts.ndjson   every judged record with the judge's answer
  WORK/alerts.ndjson     the ones it flagged
  WORK/reviews.ndjson    each alert with the reviewer's finding
  WORK/reviewed/verdicts.ndjson   the verdicts again, an alert the reviewer found benign no longer flagged

score_v2.py scores WORK for the judge alone and WORK/reviewed for both.

What differs from the config init writes:

- The sources are two sockets, `events` for the windows and `learn` for
  history. Each pack's plugin is there twice, the second copy taking `learn`
  and feeding only the baseline and the lake.
- The waits are seconds, not an hour and a minute: a year of history cannot
  be played at its own pace. The player stops before each window until the
  lake has what came before it, and after it until its verdicts are back, so
  two windows of one actor are never one group.
- The models are init's, Claude Haiku 5.5 as judge and Claude Sonnet 5.5 as
  reviewer, on ANTHROPIC_API_KEY. With OPENROUTER_API_KEY set instead they
  are asked through OpenRouter, held to Anthropic as the host.

`tangent` is the one on the PATH, or TANGENT. PROFILE is the profile.yaml
(profile/profile.yaml here), DATA the directory of address data
(examples/enrich/setup.sh in tangent's repository fetches it). SOURCES names
init's sources (cloudtrail,github,okta,google_workspace).
"""
import json
from datetime import datetime, timedelta
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

HOLD = 3         # seconds of quiet that close an actor's group, and an actor's alerts
STALL = 60       # seconds with no new verdict before a window is given up on
LAKE = 300       # seconds with no new hour in the lake before a window goes on without it
LIMIT = 900      # seconds to wait at the end for the reviews


def config(text, events, learn, packs):
    def sub(a, b, n=1):
        nonlocal text
        if text.count(a) != n:
            sys.exit(f"tangent.yaml is not as this script knows it: {a!r} is there {text.count(a)} times, not {n}")
        text = text.replace(a, b)

    head, rest = text.split("\nsources:\n", 1)
    _, rest = rest.split("\nplugins:\n", 1)
    text = (head + f"\nsources:\n  events:\n    type: socket\n    socket_path: {events}\n"
            f"  learn:\n    type: socket\n    socket_path: {learn}\n\nplugins:\n" + rest)
    prebuilt = "prebuilt: { repo: EthanBlackburn/tangent, workflow: .github/workflows/attest-packs.yml"
    for p in packs:
        m = re.search(rf"\n  {p}:\n    inputs: \[\w+\]\n", text)
        if not m:
            sys.exit(f"tangent.yaml has no plugin {p}")
        text = text.replace(m.group(0), f"\n  {p}:\n    inputs: [events]\n", 1)
        text = text.replace("\nplugins:\n", f"\nplugins:\n  {p}_learn:\n    inputs: [learn]\n    module_type: rust\n"
                            f"    {prebuilt}, asset: {p}.component.wasm }}\n", 1)
    both = ", ".join(packs)
    more = ", ".join(packs + [p + "_learn" for p in packs])
    sub(f"  baseline_builder:\n    inputs: [{both}]", f"  baseline_builder:\n    inputs: [{more}]")
    sub(f"  lake:\n    inputs: [{both}]", f"  lake:\n    inputs: [{more}]")
    sub("    max_age_ms: 3600000 ", f"    max_age_ms: {HOLD * 1000} ")
    sub("    expire_after_ms: 3600000 ", f"    expire_after_ms: {HOLD * 1000} ")
    sub("    expire_after_ms: 60000 ", f"    expire_after_ms: {HOLD * 1000} ")
    if os.environ.get("OPENROUTER_API_KEY"):
        sub("    type: anthropic\n", "    type: openai\n    url: https://openrouter.ai/api/v1\n", 2)
        sub('"${ANTHROPIC_API_KEY}"', '"${OPENROUTER_API_KEY}"', 2)
        sub("    model: claude-haiku-5-5\n", "    model: anthropic/claude-haiku-5.5\n")
        sub("    model: claude-sonnet-5-5\n", "    model: anthropic/claude-sonnet-5.5\n")
        sub("    fallback: claude-sonnet-5 ", "    fallback: anthropic/claude-sonnet-5 ")
        sub("extra: { thinking: { type: disabled } }", "extra: { provider: { order: [anthropic], allow_fallbacks: false } }")
        sub("      thinking: { type: adaptive }", "      provider: { order: [anthropic], allow_fallbacks: false }")
        sub("      output_config: { effort: low }\n", "      reasoning: { effort: low }\n")
    elif not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("set ANTHROPIC_API_KEY, or OPENROUTER_API_KEY")
    return text


def count(path):
    try:
        with open(path, "rb") as f:
            return sum(1 for _ in f)
    except OSError:
        return 0


def kept(work, start):
    """Wait until the lake has written what came before a window that opens
    at `start`: its sink falls months behind a year played in minutes, and a
    review would find the table empty. The last day is in files the sink has
    open, which a query reads too."""
    logs = os.path.join(work, "lake", "logs")
    want = (datetime.strptime(start[:13], "%Y-%m-%dT%H") - timedelta(days=1)).strftime("%Y/%m/%d/%H")
    seen, since = None, time.time()
    while True:
        newest = logs
        try:
            for _ in range(4):
                newest = os.path.join(newest, max(os.listdir(newest)))
        except (OSError, ValueError):
            pass
        newest = os.path.relpath(newest, logs)
        if newest != seen:
            seen, since = newest, time.time()
        if (len(newest) == len(want) and newest >= want) or time.time() - since > LAKE:
            return
        time.sleep(1)


def connect(path):
    for _ in range(600):
        if os.path.exists(path):
            break
        time.sleep(0.1)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(path)
    return s


def reviewed(work):
    """verdicts.ndjson with each alert the reviewer found benign unflagged."""
    def key(r):
        return json.dumps({k: v for k, v in r.items() if k not in ("judge", "review", "reviewed")}, sort_keys=True)
    benign = set()
    try:
        with open(os.path.join(work, "reviews.ndjson")) as f:
            for line in f:
                r = json.loads(line)
                if (r.get("review") or {}).get("verdict") == "benign":
                    benign.add(key(r))
    except OSError:
        pass
    os.makedirs(os.path.join(work, "reviewed"), exist_ok=True)
    with open(os.path.join(work, "verdicts.ndjson")) as f, open(os.path.join(work, "reviewed", "verdicts.ndjson"), "w") as out:
        for line in f:
            r = json.loads(line)
            if key(r) in benign:
                r["judge"] = dict(r["judge"], flag=False, cleared="reviewer")
            out.write(json.dumps(r) + "\n")
    return len(benign)


def main():
    if len(sys.argv) != 4:
        sys.exit(__doc__.split("\n\n")[0])
    stream, windows, work = (os.path.abspath(a) for a in sys.argv[1:4])
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    tangent = os.environ.get("TANGENT") or shutil.which("tangent") or sys.exit("no tangent on the PATH: set TANGENT")
    packs = os.environ.get("SOURCES", "cloudtrail,github,okta,google_workspace").split(",")
    profile = os.environ.get("PROFILE", os.path.join(here, "profile", "profile.yaml"))
    data = os.environ.get("DATA") or sys.exit("set DATA to the directory of address data")
    if os.path.exists(work) and os.listdir(work):
        sys.exit(f"{work} is not empty")
    os.makedirs(work, exist_ok=True)
    with open(windows) as f:
        windows = [tuple(w) for w in json.load(f)]

    with open(os.path.join(work, "init.log"), "w") as log:
        if subprocess.run([tangent, "init", "cloud", "--sources", ",".join(packs)], cwd=work, stdout=log, stderr=subprocess.STDOUT).returncode:
            sys.exit(f"tangent init failed: see {work}/init.log")
    shutil.copy(profile, os.path.join(work, "profile.yaml"))
    os.symlink(os.path.abspath(data), os.path.join(work, "data"))
    socks = tempfile.mkdtemp(prefix="release-")   # a socket's path is at most 104 bytes
    events, learn = os.path.join(socks, "events.sock"), os.path.join(socks, "learn.sock")
    path = os.path.join(work, "tangent.yaml")
    with open(path) as f:
        text = config(f.read(), events, learn, packs)
    with open(path, "w") as f:
        f.write(text)

    verdicts, alerts, reviews = (os.path.join(work, n) for n in ("verdicts.ndjson", "alerts.ndjson", "reviews.ndjson"))
    with open(os.path.join(work, "run.log"), "w") as log:
        proc = subprocess.Popen([tangent, "watch", "--config", "tangent.yaml", "--no-notify"], cwd=work, stdout=log, stderr=subprocess.STDOUT)
        try:
            to = {True: connect(events), False: connect(learn)}
            sent = w = 0
            inside = False

            def settle():
                """Wait for the window's verdicts, then for its groups to close."""
                changed, seen = time.time(), -1
                while proc.poll() is None:
                    now = count(verdicts)
                    if now >= sent:
                        break
                    if now != seen:
                        seen, changed = now, time.time()
                    elif time.time() - changed > STALL:
                        print(f"window {w}: {now} of {sent} verdicts, going on", flush=True)
                        break
                    time.sleep(0.5)
                time.sleep(HOLD + 1)

            with open(stream, "rb") as f:
                for line in f:
                    at = line.find(b'"ts":"')
                    ts = line[at + 6:line.find(b'"', at + 6)].decode()
                    while w < len(windows) and ts > windows[w][1]:
                        if inside:
                            settle()
                            print(f"window {w + 1}/{len(windows)}: {count(verdicts)} verdicts, {count(alerts)} alerts, {count(reviews)} reviews", flush=True)
                            inside = False
                        w += 1
                    judged = w < len(windows) and ts >= windows[w][0]
                    if judged and not inside:
                        time.sleep(1)          # what came before is learned first,
                        kept(work, windows[w][0])   # and in the lake
                        inside = True
                    to[judged].sendall(line if line.endswith(b"\n") else line + b"\n")
                    sent += judged
                    if proc.poll() is not None:
                        sys.exit(f"tangent stopped: see {work}/run.log")
            if inside:
                settle()
            began = changed = time.time()
            seen = None
            while proc.poll() is None and time.time() - began < LIMIT:
                now = (count(alerts), count(reviews))
                if now != seen:
                    seen, changed = now, time.time()
                if now[1] >= now[0] and time.time() - changed > 3 * HOLD + 10:
                    break
                time.sleep(2)
        finally:
            if proc.poll() is None:
                proc.send_signal(signal.SIGTERM)
                proc.wait()
            shutil.rmtree(socks, ignore_errors=True)
    cleared = reviewed(work)
    print(f"{sent} records judged: {count(verdicts)} verdicts, {count(alerts)} alerts, {count(reviews)} reviews, {cleared} found benign")


if __name__ == "__main__":
    main()
