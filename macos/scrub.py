"""scrub.py ES NET OUT_DIR: a recording without the recorder in it.

ES is the capture as record.sh brings it back (process snapshots, the
capture's `monitor` line, the sensor's lines; plain or .zst) and NET is
net.py's lines. What the capture did itself is taken out: the `monitor` line,
every process at or under the pid it names (by the snapshots' parents and the
sensor's forks) with their events and connections, and any event that names
the recorder's own directory in the VM. On a real Mac the sensor is a daemon
and none of this exists; left in, it is a login that announces it is the
capture, which a judge reads as someone covering their tracks.

Writes OUT_DIR/es.ndjson.zst and OUT_DIR/net.ndjson. Needs zstd on the PATH.
"""
import json
import os
import subprocess
import sys

REC = "/private/var/tmp/rec"   # record.sh's directory in the VM


def lines(path):
    if path.endswith(".zst"):
        p = subprocess.Popen(["zstd", "-dc", path], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        yield from p.stdout
        if p.wait():
            sys.exit(f"zstd could not read {path}")
    else:
        with open(path) as f:
            yield from f


def main():
    if len(sys.argv) != 4:
        sys.exit(__doc__.split("\n\n")[0])
    es, net, out = sys.argv[1:]
    # the head: snapshots and the monitor line, all before the first event
    monitor = None
    parents = {}
    for line in lines(es):
        if '"event"' in line[:20] or '"event_type"' in line:
            break
        e = json.loads(line)
        if "monitor" in e:
            monitor = e["monitor"]["pid"]
        elif "ps" in e:
            parents[e["ps"]["pid"]] = e["ps"]["ppid"]
    if monitor is None:
        sys.exit(f"{es} has no monitor line: already scrubbed, or not a capture")
    tree = {monitor}
    grew = True
    while grew:
        grew = False
        for pid, ppid in parents.items():
            if ppid in tree and pid not in tree:
                tree.add(pid)
                grew = True

    kept = dropped = 0
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "es.ndjson.zst.tmp"), "wb") as raw:
        z = subprocess.Popen(["zstd", "-q", "-3", "-c"], stdin=subprocess.PIPE, stdout=raw, text=True)
        for line in lines(es):
            e = json.loads(line)
            if "monitor" in e:
                continue
            if "ps" in e:
                keep = e["ps"]["pid"] not in tree
            else:
                pid = e["process"]["audit_token"]["pid"]
                fork = e["event"].get("fork")
                if fork and pid in tree:
                    tree.add(fork["child"]["audit_token"]["pid"])
                keep = pid not in tree and REC not in line
            if keep:
                z.stdin.write(line)
                kept += 1
            else:
                dropped += 1
        z.stdin.close()
        if z.wait():
            sys.exit("zstd failed")
    connections = 0
    with open(net) as f, open(os.path.join(out, "net.ndjson.tmp"), "w") as o:
        for line in f:
            n = json.loads(line)["net"]
            if n.get("pid") in tree or n.get("epid") in tree:
                dropped += 1
                continue
            o.write(line)
            connections += 1
    for name in ("es.ndjson.zst", "net.ndjson"):
        os.replace(os.path.join(out, name + ".tmp"), os.path.join(out, name))
    print(f"{kept} sensor lines and {connections} connections kept; {dropped} of the recorder's own taken out")


if __name__ == "__main__":
    main()
