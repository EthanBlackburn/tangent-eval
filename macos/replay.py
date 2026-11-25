"""replay.py RECORDING WORK: a recording through tangent as it ships.

RECORDING is a directory record.sh wrote (es.ndjson.zst, net.ndjson,
prompts.ndjson). Its lines are put in one stream in time order, as the
`macos` source delivers them, and played into the pipeline that
`tangent init mac --hosted` writes, each line when its time comes round: a
review ten seconds after an alert finds only what had happened by then. The
judge reads each session and the reviewer each alert, which costs money. It
is stopped once every alert has its review and nothing new has come for a
while.

  WORK/stream.ndjson     the merged stream
  WORK/tangent.yaml      the pipeline, as init wrote it but for what is below
  WORK/verdicts.ndjson   each session's summary with the judge's answer
  WORK/alerts.ndjson     what tangent would tell a person of
  WORK/reviews.ndjson    each alert with the reviewer's finding

Two things differ from the config init writes: the source is a socket the
recording is played into, and the reviewer's `data` is an empty directory,
so it reads no file of the Mac this runs on.

The models are init's, Claude Haiku 5.5 as judge and Claude Sonnet 5.5 as
reviewer, on ANTHROPIC_API_KEY. With OPENROUTER_API_KEY set instead they are
asked through OpenRouter, held to Anthropic as the host.

`tangent` is the one on the PATH, or TANGENT. Needs zstd on the PATH.
"""
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime

QUIET = 200      # seconds with nothing new, after the last line is played, before the run is taken as done
LIMIT = 3000     # and the longest one may take


def merge(recording, out_path):
    """The sensor's lines in their order, each connection and each prompt put
    before the first sensor event that is later than it."""
    other = []
    for name in ("net.ndjson", "prompts.ndjson"):
        try:
            with open(os.path.join(recording, name)) as f:
                other += [(json.loads(line)["time"], line) for line in f if line.strip()]
        except OSError:
            pass   # a recording from before prompts were captured
    other.sort()
    es = subprocess.Popen(["zstd", "-dc", os.path.join(recording, "es.ndjson.zst")], stdout=subprocess.PIPE, text=True)
    i = lines = 0
    with open(out_path, "w") as out:
        for line in es.stdout:
            at = line.find('"time":"')
            if at >= 0 and '"event"' in line:
                t = line[at + 8:at + 38]
                while i < len(other) and other[i][0] < t:
                    out.write(other[i][1])
                    i += 1
            out.write(line)
            lines += 1
        for _, line in other[i:]:
            out.write(line)
    if es.wait():
        sys.exit(f"zstd could not read {recording}/es.ndjson.zst")
    return lines, len(other)


def config(text, sock):
    """init's tangent.yaml with the source a socket and no file to read, and
    with OPENROUTER_API_KEY its models asked through OpenRouter."""
    def sub(a, b, n=1):
        nonlocal text
        if text.count(a) != n:
            sys.exit(f"tangent.yaml is not as this script knows it: {a!r} is there {text.count(a)} times, not {n}")
        text = text.replace(a, b)

    sub("  mac:\n    type: macos\n", f"  mac:\n    type: socket\n    socket_path: {sock}\n")
    sub("    data: /  ", "    data: nothing  ")
    if os.environ.get("OPENROUTER_API_KEY"):
        sub("    type: anthropic\n", "    type: openai\n    url: https://openrouter.ai/api/v1\n", 2)
        sub('"${ANTHROPIC_API_KEY}"', '"${OPENROUTER_API_KEY}"', 2)
        sub("    model: claude-haiku-5-5\n", "    model: anthropic/claude-haiku-5.5\n")
        sub("    model: claude-sonnet-5-5\n", "    model: anthropic/claude-sonnet-5.5\n")
        sub("    fallback: claude-sonnet-5 ", "    fallback: anthropic/claude-sonnet-5 ")
        sub("      thinking: { type: adaptive }", "      provider: { order: [anthropic], allow_fallbacks: false }", 2)
        for effort in ("low", "medium"):
            sub(f"      output_config: {{ effort: {effort} }}\n", f"      reasoning: {{ effort: {effort} }}\n")
    elif not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("set ANTHROPIC_API_KEY, or OPENROUTER_API_KEY")
    return text


def when(line):
    """A line's `time`, in seconds; None when it has none."""
    for key in (b'"time":"', b'"time": "'):
        at = line.find(key)
        if at >= 0:
            day, _, rest = line[at + len(key):line.find(b'"', at + len(key))].decode().rstrip("Z").partition(".")
            try:
                return datetime.fromisoformat(day + "+00:00").timestamp() + float("0." + (rest or "0"))
            except ValueError:
                return None
    return None


def play(stream, sock, state):
    """Each line of the stream into the socket, at the pace it was recorded."""
    for _ in range(600):
        if os.path.exists(sock):
            break
        time.sleep(0.1)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sock)
    first = began = None
    with open(stream, "rb") as f:
        for line in f:
            t = when(line)
            if t is not None:
                if first is None:
                    first, began = t, time.time()
                wait = (t - first) - (time.time() - began)
                if wait > 0:
                    time.sleep(wait)
            s.sendall(line if line.endswith(b"\n") else line + b"\n")
    s.close()
    state["played"] = time.time()


def count(path):
    try:
        with open(path, "rb") as f:
            return sum(1 for _ in f)
    except OSError:
        return 0


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__.split("\n\n")[0])
    recording, work = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    tangent = os.environ.get("TANGENT") or shutil.which("tangent") or sys.exit("no tangent on the PATH: set TANGENT")
    if os.path.exists(work) and os.listdir(work):
        sys.exit(f"{work} is not empty")
    os.makedirs(os.path.join(work, "nothing"))
    lines, others = merge(recording, os.path.join(work, "stream.ndjson"))
    print(f"{lines} sensor lines, {others} connections and prompts", flush=True)

    with open(os.path.join(work, "init.log"), "w") as log:
        if subprocess.run([tangent, "init", "mac", "--hosted"], cwd=work, stdout=log, stderr=subprocess.STDOUT).returncode:
            sys.exit(f"tangent init failed: see {work}/init.log")
    sock = os.path.join(tempfile.mkdtemp(prefix="replay-"), "in.sock")   # a socket's path is at most 104 bytes
    path = os.path.join(work, "tangent.yaml")
    with open(path) as f:
        text = config(f.read(), sock)
    with open(path, "w") as f:
        f.write(text)

    outs = [os.path.join(work, f) for f in ("verdicts.ndjson", "alerts.ndjson", "reviews.ndjson")]
    state = {"played": None}
    with open(os.path.join(work, "run.log"), "w") as log:
        proc = subprocess.Popen([tangent, "watch", "--config", "tangent.yaml", "--no-notify"], cwd=work, stdout=log, stderr=subprocess.STDOUT)
        threading.Thread(target=play, args=(os.path.join(work, "stream.ndjson"), sock, state), daemon=True).start()
        started = changed = time.time()
        seen = None
        while proc.poll() is None:
            time.sleep(5)
            now = [count(p) for p in outs]
            if now != seen:
                seen, changed = now, time.time()
            quiet = time.time() - max(changed, state["played"] or time.time())
            if (now[2] >= now[1] and quiet > QUIET) or time.time() - started > LIMIT:
                proc.send_signal(signal.SIGTERM)
                proc.wait()
    shutil.rmtree(os.path.dirname(sock), ignore_errors=True)
    if state["played"] is None:
        sys.exit(f"tangent stopped before the recording was played: see {work}/run.log")
    print(f"{seen[0]} verdicts, {seen[1]} alerts, {seen[2]} reviews" + ("" if seen[2] >= seen[1] else ": stopped before every alert was reviewed"))


if __name__ == "__main__":
    main()
