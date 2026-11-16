"""Elastic's macOS detection rules (EQL) over the recordings.

    python3 -I elastic.py RULES RECORDINGS [--public] > elastic-results.json

RULES is a checkout of elastic/detection-rules; the rules read are those of
rules/macos and rules/cross-platform tagged `OS: macOS` and written in EQL,
evaluated by Elastic's own `eql` package. Rules of the other types are listed
as skipped, by type.

Each recording becomes the events Elastic Defend would index (ECS): a process
event an exec, a file event a file created, renamed, written, deleted or opened (Elastic
Defend indexes the opening of chosen files only; here every one is given), a
network event a connection. A process's entity id is its pid and how many
times that pid has exec'd.

The engine compares strings without regard to case, which Elasticsearch does
only where a rule asks for it, so a rule can match here and not there, never
the reverse. `--public` gives the stand-in the attacks talk to (the VM's host,
a private address) a public address, since many rules leave private addresses
out and a real attack's server would not be one."""
import glob
import ipaddress
import json
import os
import re
import sys
import tomllib
from datetime import datetime

import eql
from eql.utils import fold_case as fold

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from events import events

PUBLIC = "--public" in sys.argv
RULES, RECORDINGS = ([a for a in sys.argv[1:] if not a.startswith("--")] + [None, None])[:2]  # cloud_elastic.py imports the engine only
APPLE = ("/System/", "/usr/bin/", "/bin/", "/sbin/", "/usr/sbin/", "/usr/libexec/")


def ticks(t):
    """A time as the engine counts it: a whole number, ten million a second."""
    head, _, frac = t.rstrip("Z").partition(".")
    return int(datetime.fromisoformat(head + "+00:00").timestamp()) * 10_000_000 + int((frac + "0000000")[:7])


def signature(image, signing_id, team_id, platform):
    if signing_id is None and team_id is None and platform is None:  # running before the recording began
        platform = image.startswith(APPLE)
        signing_id = "com.apple." + os.path.basename(image) if platform else None
    exists = bool(platform or signing_id or team_id)
    return {"exists": exists, "trusted": bool(platform or team_id), "signing_id": signing_id, "team_id": team_id,
            "subject_name": "Software Signing" if platform else (f"Developer ID Application: ({team_id})" if team_id else None)}


def proc(image, args, cmdline, sig, pid, entity):
    return {"name": os.path.basename(image), "executable": image, "args": args, "args_count": len(args),
            "command_line": cmdline, "pid": pid, "entity_id": entity, "code_signature": sig}


def ecs(d):
    """The recording at `d` as (event type, ticks, ECS document) in time order."""
    out, live, count = [], {}, {}  # live: pid -> the process document it is now
    base = {"host": {"os": {"type": "macos"}, "id": "vm", "hostname": "vm"}, "user": {"name": "admin", "id": "501"}}

    def now(pid, e):
        if pid not in live:
            live[pid] = proc(e["image"], e.get("args") or [], e.get("cmdline") or "",
                             signature(e["image"], e.get("signing_id"), e.get("team_id"), e.get("platform")), pid, f"{pid}-0")
        return live[pid]

    for e in events(d):
        t = ticks(e["time"])
        if e["kind"] == "process":
            pid = e["pid"]
            before = live.get(pid)
            parent = live.get(e["ppid"]) or proc(e["parent_image"], e["parent_args"], e["parent_cmdline"],
                                                  signature(e["parent_image"], None, None, None), e["ppid"], f"{e['ppid']}-0")
            if e["ppid"] not in live:
                live[e["ppid"]] = parent
            count[pid] = count.get(pid, 0) + 1
            p = proc(e["image"], e["args"], e["cmdline"], signature(e["image"], e["signing_id"], e["team_id"], e["platform"]),
                     pid, f"{pid}-{count[pid]}")
            live[pid] = p
            rp = live.get(e["responsible_pid"])
            eff = rp["executable"] if rp else e["responsible_image"]
            ancestry = [parent["entity_id"]] + ((parent.get("Ext") or {}).get("ancestry") or [])
            p.update(env_vars=e["env"], working_directory=e["cwd"],
                     Ext={"ancestry": ancestry, "effective_parent": {"executable": eff, "name": os.path.basename(eff or ""),
                                                                     "entity_id": rp["entity_id"] if rp else None}})
            doc = dict(p, parent={k: v for k, v in parent.items() if k != "parent"})
            live[pid] = doc
            if before:
                doc["previous"] = {"executable": before["executable"]}
            out.append(("process", t, {**base, "event": {"category": "process", "type": "start", "action": "exec", "kind": "event"},
                                       "process": doc}))
        elif e["kind"] == "file":
            f = {"path": e["path"], "name": os.path.basename(e["path"]), "extension": os.path.splitext(e["path"])[1].lstrip(".")}
            if e["from"]:
                f["Ext"] = {"original": {"path": e["from"], "name": os.path.basename(e["from"])}}
            kind = {"creation": "creation", "rename": "change", "modification": "change", "deletion": "deletion", "open": "access"}[e["action"]]
            out.append(("file", t, {**base, "event": {"category": "file", "type": kind, "action": e["action"], "kind": "event", "outcome": "success"},
                                    "file": f, "process": now(e["pid"], e)}))
        else:
            p = live.get(e["pid"]) or proc(e["image"] or e["proc"] or "", e["args"], e["cmdline"],
                                           signature(e["image"] or "", None, None, None), e["pid"], f"{e['pid']}-0")
            dst = e["dst"]
            if PUBLIC and dst and dst.startswith("192.168.64."):
                dst = "45.33.32.156"
            doc = {**base, "event": {"category": "network", "type": "start", "action": "connection_attempted", "kind": "event"},
                   "network": {"direction": "egress"}, "destination": {"ip": dst, "port": e["port"], "domain": e["host"] or None},
                   "source": {"ip": "192.168.64.2"}, "process": p}
            if e["host"]:
                doc["dns"] = {"question": {"name": e["host"]}}
            out.append(("network", t, doc))
    return out


class Engine(eql.PythonEngine):
    """Elasticsearch's reading where the package's engine has none: a field with several
    values (process.args) matches when any of them does, and `cidrmatch` knows IPv6."""

    def _convert_in_set(self, node):
        if not all(isinstance(i, eql.ast.Literal) for i in node.container):
            return self.convert(node.synonym)
        values, get = {fold(i.value) for i in node.container}, self.convert(node.expression)

        def callback(scope):
            v = get(scope)
            if v is None:
                return None
            return any(fold(x) in values for x in v) if isinstance(v, list) else fold(v) in values
        return callback

    def _convert_comparison(self, node):
        one = super()._convert_comparison(node)
        get_left, get_right = self.convert(node.left), self.convert(node.right)
        compare = self.check_types(self.lowercase(node.function, always=False))

        def callback(scope):
            left = get_left(scope)
            if not isinstance(left, list):
                return one(scope)
            got = [compare(x, get_right(scope)) for x in left]
            return all(got) if node.comparator == "!=" else any(got)
        return callback

    def _convert_function_call(self, node):
        if node.name.lower() == "cidrmatch":
            nets = [ipaddress.ip_network(a.value, strict=False) for a in node.arguments[1:]]
            get = self.convert(node.arguments[0])

            def cidr(scope):
                try:
                    ip = ipaddress.ip_address(get(scope))
                except ValueError:
                    return None
                return any(ip.version == n.version and ip in n for n in nets)
            return cidr
        if node.name == "wildcard" and all(isinstance(a, eql.ast.String) for a in node.arguments[1:]):  # `*` and `?`, as Elasticsearch reads `like`
            pattern = re.compile("|".join("".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in fold(a.value))
                                          for a in node.arguments[1:]), re.S)
            get = self.convert(node.arguments[0])

            def like(scope):
                v = get(scope)
                if v is None:
                    return None
                return any(isinstance(x, str) and pattern.fullmatch(fold(x)) is not None for x in (v if isinstance(v, list) else [v]))
            return like
        if node.name in ("match", "matchLite") and all(isinstance(a, eql.ast.String) for a in node.arguments[1:]):  # the whole value, as Elasticsearch reads `regex`
            pattern = re.compile("|".join(f"(?:{a.value})" for a in node.arguments[1:]), re.I | re.S)
            get = self.convert(node.arguments[0])

            def regex(scope):
                v = get(scope)
                if v is None:
                    return None
                return any(isinstance(x, str) and pattern.fullmatch(x) is not None for x in (v if isinstance(v, list) else [v]))
            return regex
        one = super()._convert_function_call(node)
        if node.name not in ("wildcard", "match", "matchLite", "startsWith", "endsWith", "stringContains"):
            return one
        get = self.convert(node.arguments[0])
        func = self._functions.get(node.name, node.signature)
        func = func.get_callback(*node.arguments) if hasattr(func, "get_callback") else func
        rest = self._convert_tuple(node.arguments[1:])

        def callback(scope):
            v = get(scope)
            return any(func(x, *rest(scope)) for x in v) if isinstance(v, list) else one(scope)
        return callback


def rules():
    read, skipped, failed = [], {}, []
    for f in sorted(glob.glob(os.path.join(RULES, "rules/macos/*.toml")) + glob.glob(os.path.join(RULES, "rules/cross-platform/*.toml"))):
        doc = tomllib.load(open(f, "rb"))
        r = doc["rule"]
        if "OS: macOS" not in r.get("tags", []) or doc["metadata"].get("maturity") == "deprecated":
            continue
        kind = r["type"] if r["type"] != "query" else r.get("language")
        if kind != "eql":
            skipped.setdefault(kind, []).append(r["name"])
            continue
        try:
            with eql.parser.elasticsearch_syntax, eql.parser.ignore_missing_functions, eql.parser.allow_sample, eql.parser.allow_runs:
                read.append((r, eql.parse_query(r["query"])))
        except eql.EqlError as x:
            failed.append({"rule": r["name"], "error": str(x).splitlines()[0][:200]})
    return read, skipped, failed


def run(read, evs):
    hits = {}
    for r, q in read:
        engine = Engine()
        got = []
        try:
            engine.add_query(q)
            engine.add_output_hook(got.append)
            engine.stream_events(eql.Event(k, t, doc) for k, t, doc in evs)
        except Exception as x:  # a rule the engine cannot run is reported, not counted quiet
            hits[r["name"]] = {"error": f"{type(x).__name__}: {x}"[:200]}
            continue
        if got:
            first = got[0].events[-1].data
            hits[r["name"]] = {"severity": r["severity"], "count": len(got),
                               "first": (first.get("process") or {}).get("command_line") or (first.get("file") or {}).get("path")}
    return hits


if __name__ == "__main__":
    read, skipped, failed = rules()
    out = {"rules": len(read), "skipped": {k: len(v) for k, v in skipped.items()}, "skipped_names": skipped, "unparsed": failed, "cases": {}}
    for case in sorted(os.listdir(RECORDINGS)):
        for side in ("attack", "twin"):
            d = os.path.join(RECORDINGS, case, side)
            if os.path.isdir(d):
                evs = ecs(d)
                out["cases"][f"{case}/{side}"] = run(read, evs)
                print(case, side, len(evs), "events", len(out["cases"][f"{case}/{side}"]), "rules", file=sys.stderr, flush=True)
    json.dump(out, sys.stdout, indent=1)
