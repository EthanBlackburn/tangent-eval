"""A recording (eslogger's es.ndjson.zst and the capture's net.ndjson) as flat
events a rule engine can read: one dict a process start, file event or connection.

    events(dir) -> list of dicts, in time order

A process start is an `exec`. Its parent is the process whose pid is the new
image's `ppid`, as last exec'd (or as the `ps` snapshot at the start of the
recording has it); when neither knows the pid, the image the process had before
this exec, which after a fork is the parent's."""
import json
import os
import subprocess


def path(o):
    return (o or {}).get("path") or ""


def events(d):
    out, procs = [], {}  # pid -> {image, cmdline, args}
    es = os.path.join(d, "es.ndjson.zst")
    for line in subprocess.run(["zstd", "-dc", es], capture_output=True, check=True).stdout.splitlines():
        r = json.loads(line)
        if "ps" in r:
            procs[r["ps"]["pid"]] = {"image": r["ps"]["path"], "cmdline": r["ps"].get("args") or r["ps"]["path"], "args": []}
            continue
        ev, p = r.get("event") or {}, r.get("process") or {}
        pid = (p.get("audit_token") or {}).get("pid")
        me = {"pid": pid, "image": path(p.get("executable")), "signing_id": p.get("signing_id"), "team_id": p.get("team_id"),
              "platform": p.get("is_platform_binary")}
        if "exec" in ev:
            x = ev["exec"]
            t = x["target"]
            args = x.get("args") or []
            parent = procs.get(t.get("ppid")) or {"image": me["image"], "cmdline": "", "args": []}
            if pid == t.get("ppid") or t.get("ppid") not in procs:
                pass
            e = {"kind": "process", "time": r["time"], "pid": pid, "ppid": t.get("ppid"), "image": path(t.get("executable")),
                 "args": args, "cmdline": " ".join(args), "parent_image": parent["image"], "parent_cmdline": parent["cmdline"],
                 "parent_args": parent["args"], "signing_id": t.get("signing_id"), "team_id": t.get("team_id"),
                 "platform": t.get("is_platform_binary"), "cs_flags": t.get("codesigning_flags"),
                 "cwd": path(x.get("cwd")), "env": x.get("env") or [], "script": path(x.get("script")),
                 "responsible_pid": (t.get("responsible_audit_token") or {}).get("pid"), "tty": path(t.get("tty"))}
            rp = procs.get(e["responsible_pid"])
            e["responsible_image"] = rp["image"] if rp else ""
            # the parent of the first exec after a fork is the forker; a re-exec keeps its parent
            procs[pid] = {"image": e["image"], "cmdline": e["cmdline"], "args": args}
            out.append(e)
        elif "fork" in ev:
            c = ev["fork"]["child"]
            cp = (c.get("audit_token") or {}).get("pid")
            procs.setdefault(cp, dict(procs.get(pid) or {"image": me["image"], "cmdline": "", "args": []}))
            if pid in procs:
                procs[cp] = dict(procs[pid])
        else:
            cur = procs.get(pid) or {"image": me["image"], "cmdline": "", "args": []}
            f = None
            if "create" in ev:
                dst = ev["create"]["destination"]
                f = ("creation", path(dst.get("existing_file")) or os.path.join(path((dst.get("new_path") or {}).get("dir")), (dst.get("new_path") or {}).get("filename") or ""), "")
            elif "rename" in ev:
                dst = ev["rename"]["destination"]
                f = ("rename", path(dst.get("existing_file")) or os.path.join(path((dst.get("new_path") or {}).get("dir")), (dst.get("new_path") or {}).get("filename") or ""), path(ev["rename"]["source"]))
            elif "unlink" in ev:
                f = ("deletion", path(ev["unlink"]["target"]), "")
            elif "close" in ev and ev["close"].get("modified"):
                f = ("modification", path(ev["close"]["target"]), "")
            elif "open" in ev:
                f = ("open", path(ev["open"]["file"]), "")
            if f:
                out.append({"kind": "file", "time": r["time"], "action": f[0], "path": f[1], "from": f[2], **me,
                            "cmdline": cur["cmdline"], "args": cur["args"]})
    net = os.path.join(d, "net.ndjson")
    if os.path.exists(net):
        for line in open(net):
            r = json.loads(line)
            n = r.get("net") or {}
            cur = procs.get(n.get("pid")) or {}
            out.append({"kind": "network", "time": r["time"], "pid": n.get("pid"), "proc": n.get("proc"), "image": cur.get("image") or "",
                        "cmdline": cur.get("cmdline") or "", "args": cur.get("args") or [],
                        "dst": n.get("dst"), "port": n.get("port"), "host": n.get("host") or n.get("sni") or ""})
    out.sort(key=lambda e: e["time"])
    return out
