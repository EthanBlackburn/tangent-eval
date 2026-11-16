"""Elastic's cloud detection rules over the cloud corpus, run by Elasticsearch itself.

    python3 -I cloud_es.py RULES STREAM TRUTH WINDOWS RUN_VERDICTS OUT [--level medium] [--es http://127.0.0.1:9209] [--keep]

The corpus is indexed as cloud_elastic.py maps it (the fields Elastic's
integrations index), into data streams named as the integrations name theirs
(logs-aws.cloudtrail-default, ...), every string a keyword, addresses `ip`, the
`flattened` objects `flattened`. Each rule of rules/integrations/{aws,okta,
github,google_workspace} is then run against the indices it names:

  KQL        the `kql` query
  EQL        _eql/search (an event type other than `any` is read as `any`: the corpus has no
             event.category; `stringContains` of a text with `*` in it is read as `like`)
  ES|QL      _query. A rule that keeps `_id` is run once over the whole log. One that aggregates
             is run as Kibana schedules it, every `interval` with its lookback (`from`), at the
             ticks whose lookback reaches a scored window; an alert's records are those of its
             lookback that share its values (the columns that are fields of the log).
  new terms  the KQL query's matches, then the fields taking a value not seen in the history
             window; a case's records are not in another case's history, as in tangent's runs
  threshold  the KQL query's matches, then the count (and cardinality) within the lookback

Machine-learning rules and rules over other rules' alerts are not run.
OUT/rules.json lists what fired, what failed and why, and what was not run."""
import glob
import json
import os
import re
import sys
import tomllib
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import corpus
from cloud_elastic import DIRS, LEVELS, MAP, ms, prune, span

ARGV = sys.argv[1:]


def opt(name, default=None):
    return ARGV[ARGV.index(name) + 1] if name in ARGV else default


ES = opt("--es", "http://127.0.0.1:9209")
STREAMS = {"cloudtrail": "logs-aws.cloudtrail-default", "okta": "logs-okta.system-default", "github_audit": "logs-github.audit-default"}


def call(method, path, body=None, ok=(200, 201)):
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
    req = urllib.request.Request(ES + path, data=data, method=method,
                                 headers={"content-type": "application/x-ndjson" if isinstance(body, bytes) else "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=300) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def iso(t):
    from datetime import datetime, timezone
    return datetime.fromtimestamp(t / 1000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{t % 1000:03d}Z"


def index(records):
    call("DELETE", "/_data_stream/logs-*-default?expand_wildcards=all")
    flat = {"type": "flattened"}
    status, r = call("PUT", "/_index_template/siem-compare", {
        "index_patterns": ["logs-*-default"], "priority": 900, "data_stream": {},
        "template": {"settings": {"number_of_shards": 1, "number_of_replicas": 0, "index.mapping.total_fields.limit": 20000},
                     "mappings": {"date_detection": False, "numeric_detection": False,
                                  "dynamic_templates": [{"strings": {"match_mapping_type": "string",
                                                                     "mapping": {"type": "keyword", "ignore_above": 8191}}}],
                                  "properties": {
                                      "@timestamp": {"type": "date"}, "rec": {"type": "long"},
                                      "source": {"properties": {"ip": {"type": "ip"}}}, "client": {"properties": {"ip": {"type": "ip"}}},
                                      "aws": {"properties": {"cloudtrail": {"properties": {"flattened": {"properties": {
                                          "request_parameters": flat, "response_elements": flat, "additional_eventdata": flat,
                                          "service_event_details": flat}}}}}},
                                      "okta": {"properties": {"client": {"properties": {"ip": {"type": "ip"}}},
                                                              "debug_context": {"properties": {"debug_data": {"properties": {"flattened": flat}}}}}}}}}})
    assert status == 200, r
    lines, bad, n = [], [], 0
    for i, rec in enumerate(records):
        if rec["source"] not in MAP:
            continue
        doc = prune(MAP[rec["source"]](rec))
        name = STREAMS.get(rec["source"]) or f"logs-{doc['data_stream']['dataset']}-default"
        doc["@timestamp"], doc["rec"] = rec["ts"], i
        lines.append(json.dumps({"create": {"_index": name, "_id": str(i)}}))
        lines.append(json.dumps(doc))
        n += 1
        if len(lines) >= 4000 or i == len(records) - 1:
            status, r = call("POST", "/_bulk", ("\n".join(lines) + "\n").encode())
            bad += [x["create"] for x in r.get("items", []) if x["create"].get("status", 500) >= 300]
            lines = []
    if lines:
        status, r = call("POST", "/_bulk", ("\n".join(lines) + "\n").encode())
        bad += [x["create"] for x in r.get("items", []) if x["create"].get("status", 500) >= 300]
    call("POST", "/logs-*-default/_refresh")
    return n, bad


class NotApplicable(Exception):
    pass


def target(r):
    return ",".join(r.get("index") or ["logs-*"]) + "/"


def search(r, query):
    """Every record a query matches, in time order: (record number, ms, fields)."""
    out, after = [], None
    fields = (r.get("new_terms") or {}).get("value", []) + ((r.get("threshold") or {}).get("field") or []) \
        + [c["field"] for c in (r.get("threshold") or {}).get("cardinality") or []]
    while True:
        body = {"size": 5000, "_source": False, "query": query, "sort": [{"@timestamp": "asc"}, {"rec": "asc"}],
                "fields": ["rec", {"field": "@timestamp", "format": "epoch_millis"}] + fields}
        if after:
            body["search_after"] = after
        status, res = call("POST", "/" + target(r) + "_search?ignore_unavailable=true&allow_no_indices=true", body)
        if status != 200:
            raise RuntimeError(json.dumps(res.get("error", res))[:300])
        hits = res["hits"]["hits"]
        out += [(h["fields"]["rec"][0], int(h["fields"]["@timestamp"][0]), h["fields"]) for h in hits]
        if len(hits) < 5000:
            return out
        after = hits[-1]["sort"]


def kql(r):
    q = {"kql": {"query": r["query"]}}
    return {"bool": {"filter": [q] + [f["query"] for f in r.get("filters") or [] if "query" in f]}} if r.get("filters") else q


def eql(r):
    text = re.sub(r"(^|\[)(\s*)[a-z_]+(\s+where\b)", r"\1\2any\3", r["query"], flags=re.M)
    text = re.sub(r'stringContains\(\s*([\w.]+)\s*,\s*"([^"]*\*[^"]*)"\s*\)',
                  lambda m: f'{m[1]} like "*{m[2].replace(chr(92) * 2 + "*", "?")}*"', text)
    for _ in range(40):
        status, res = call("POST", "/" + target(r) + "_eql/search?ignore_unavailable=true&allow_no_indices=true",
                           {"query": text, "size": 10000, "fetch_size": 10000, "fields": ["rec"]})
        reason = json.dumps(res.get("error", "")) if status != 200 else ""
        unknown = [m for m in re.findall(r"Unknown column \\?\[([\w.@]+)", reason)]
        if status == 200:
            break
        if "Unknown index" in reason:
            raise NotApplicable(", ".join(r.get("index") or []))
        if not unknown:
            raise RuntimeError(reason[:300])
        for name in set(unknown):  # a field of the integration that no record of the corpus has
            s2, r2 = add_field(name, guess(name))
            if s2 != 200 and (was := re.search(r"cannot be changed from type \\?\[(\w+)", json.dumps(r2))):
                add_field(name, was[1])
    if "hits" not in res:
        raise RuntimeError(json.dumps(res)[:300])
    h = res["hits"]
    events = h.get("events") or [e for s in h.get("sequences") or [] for e in s["events"]]
    return sorted({e["fields"]["rec"][0] for e in events if not e.get("missing")})


def guess(name):
    """The type Elastic's integrations give a field no record of the corpus has, by its name."""
    leaf = name.rsplit(".", 1)[-1]
    if leaf == "ip" or leaf.endswith("_ip"):
        return "ip"
    if leaf == "location":
        return "geo_point"
    if leaf in ("ingested", "created", "start", "end") or leaf.endswith(("_date", "_at", "_time")):
        return "date"
    if leaf.startswith(("is_", "has_")) or leaf.endswith(("_is_bot", "_public", "_leaked", "trusted", "_enabled")) or leaf in ("publicly_leaked", "read_only"):
        return "boolean"
    if leaf in ("number", "port", "bytes", "status_code", "count", "pid") or leaf.endswith(("_count", "_bytes", "status_code")):
        return "long"
    return "keyword"


def add_field(name, kind):
    props = {"type": kind}
    for part in reversed(name.split(".")):
        props = {"properties": {part: props}}
    return call("PUT", "/logs-*-default/_mapping", props)


def esql(query, filt=None):
    """The rule's rows as dicts; a field of the integration that no record of the corpus has is added to the mapping."""
    body = {"query": query}
    frm = re.search(r"(?i)^\s*from\s+([^\n|]+?)(\s+metadata\b|\s*$|\s*\|)", query, re.M)
    if frm:
        pats = [p.strip() for p in frm[1].split(",")]
        _, res = call("GET", "/_resolve/index/" + ",".join(pats) + "?expand_wildcards=all")
        if not (res.get("indices") or res.get("data_streams")):
            raise NotApplicable(", ".join(pats))
    if filt:
        body["filter"] = filt
    for _ in range(40):
        status, res = call("POST", "/_query", body)
        if status == 200:
            cols = [c["name"] for c in res["columns"]]
            return [dict(zip(cols, v)) for v in res["values"]]
        reason = json.dumps(res.get("error", res))
        m = re.search(r"Unknown column \[([^\]]+)\]", reason)
        if "Unknown index" in reason or "no such index" in reason:
            raise NotApplicable("its index")
        if not m or not re.fullmatch(r"[\w.@]+", m[1]) or m[1].startswith(("Esql", "_")):
            raise RuntimeError(reason[:400])
        s2, r2 = add_field(m[1], guess(m[1]))
        if s2 != 200 and (was := re.search(r"cannot be changed from type \\?\[(\w+)", json.dumps(r2))):
            s2, r2 = add_field(m[1], was[1])  # another source already has it, of this type
        if s2 != 200:
            raise RuntimeError(f"cannot map {m[1]}: " + json.dumps(r2)[:200])
    raise RuntimeError("too many unknown columns")


def main():
    args = [a for k, a in enumerate(ARGV) if not a.startswith("--") and (k == 0 or ARGV[k - 1] not in ("--level", "--es"))]
    level = opt("--level", "medium")
    root, records, truth = args[0], corpus.stream(args[1]), json.load(open(args[2]))
    windows = sorted([ms(a), ms(b)] for a, b in json.load(open(args[3])))
    case_of = {i: c["id"] for c in truth for i, *_ in c["rows"]}
    if "--keep" not in ARGV:
        n, bad = index(records)
        print(f"indexed {n} records, {len(bad)} refused" + (f": {json.dumps(bad[0])[:300]}" if bad else ""), file=sys.stderr, flush=True)
    _, caps = call("GET", "/logs-*-default/_field_caps?fields=*")
    known = {f for f, t in caps["fields"].items() if not f.startswith("_") and "object" not in t}
    at = {i: ms(r["ts"]) for i, r in enumerate(records)}
    hits, report = {}, {"fired": {}, "not_run": {}, "failed": [], "ran": 0}

    def fire(r, idx):
        idx = sorted(set(idx))
        if not idx:
            return
        c = report["fired"].setdefault(r["name"], {"severity": r["severity"], "type": r["type"], "language": r.get("language"), "count": 0})
        c["count"] += len(idx)
        if LEVELS.index(r["severity"]) >= LEVELS.index(level):
            for i in idx:
                hits.setdefault(i, []).append(r["name"])

    def attribute(r, row, lo, hi):
        """The records an aggregated alert is about: those of its lookback sharing its values."""
        terms = [{"term": {k: v}} for k, v in row.items() if k in known and isinstance(v, (str, int, bool)) and k != "@timestamp"]
        q = {"bool": {"filter": [{"range": {"@timestamp": {"gt": iso(lo), "lte": iso(hi)}}}] + terms}}
        idx_pat = re.search(r"(?i)from\s+([^\n|]+?)(\s+metadata|\s*\n|\s*\|)", r["query"])
        fake = dict(r, index=[p.strip() for p in idx_pat[1].split(",")] if idx_pat else None, new_terms=None, threshold=None)
        return [i for i, _, _ in search(fake, q)], bool(terms)

    for src, d in DIRS.items():
        for f in sorted(glob.glob(os.path.join(root, "rules/integrations", d, "*.toml"))):
            doc = tomllib.load(open(f, "rb"))
            r = doc["rule"]
            if doc["metadata"].get("maturity") == "deprecated":
                continue
            kind, lang = r["type"], r.get("language")
            if kind == "machine_learning" or ".alerts-security" in r.get("query", "") or "kibana.alert" in r.get("query", ""):
                report["not_run"].setdefault("machine learning" if kind == "machine_learning" else "reads other rules' alerts", []).append(r["name"])
                continue
            report["ran"] += 1
            try:
                if lang == "eql":
                    fire(r, eql(r))
                elif lang == "esql":
                    q = r["query"]
                    aggregates = re.search(r"(?i)\|\s*(inline\s+)?stats\b", q) is not None
                    if not aggregates:
                        rows = esql(q + "\n| LIMIT 10000")
                        if rows and "_id" in rows[0]:
                            fire(r, [int(x["_id"]) for x in rows])
                        else:
                            idx = []
                            for row in rows:
                                t = ms(row["@timestamp"]) if row.get("@timestamp") else None
                                got, _ = attribute(r, row, (t - 1) if t else windows[0][0] - 1, t if t else windows[-1][1])
                                idx += got
                            fire(r, idx)
                        continue
                    look, step = span(r.get("from"), 360000), span("now-" + (r.get("interval") or "5m"), 300000)
                    ticks = sorted({t for a, b in windows for t in range(a - a % step + step, b + look + step, step)})
                    idx, loose = [], 0
                    # one pass over the whole log says whether the rule can fire at all
                    if not esql(q):
                        whole = False
                    else:
                        whole = True
                    probe = esql(re.split(r"(?i)\|\s*(?:inline\s+)?stats\b", q)[0] + "\n| STATS n = COUNT(*)")
                    if not probe or not probe[0]["n"]:
                        continue  # nothing passes the rule's filter anywhere in the log
                    for t in ticks:
                        filt = {"range": {"@timestamp": {"gt": iso(t - look), "lte": iso(t)}}}
                        for row in esql(q, filt):
                            got, keyed = attribute(r, row, t - look, t)
                            loose += not keyed
                            idx += got
                    fire(r, idx)
                    if loose:
                        report.setdefault("unkeyed", {})[r["name"]] = loose
                    report.setdefault("whole_log", {})[r["name"]] = whole
                elif lang == "kuery":
                    matched = search(r, kql(r))
                    if kind == "query":
                        fire(r, [i for i, _, _ in matched])
                    elif kind == "new_terms":
                        nt = r["new_terms"]
                        window = span(nt["history_window_start"][0]["value"], 7 * 86400000)
                        last, idx = {}, []
                        for i, t, fl in matched:
                            vals = [fl.get(x) for x in nt["value"]]
                            if not all(vals):
                                continue
                            key = tuple(str(v[0]) for v in vals)
                            case = case_of.get(i)
                            seen = [last.get((None, key))] + ([last.get((case, key))] if case else [])
                            if not any(s is not None and t - s <= window for s in seen):
                                idx.append(i)
                            last[(case, key)] = t
                        fire(r, idx)
                    elif kind == "threshold":
                        th = r["threshold"]
                        look = span(r.get("from"), 360000)
                        groups, idx = {}, set()
                        for i, t, fl in matched:
                            key = tuple(str((fl.get(x) or [None])[0]) for x in th.get("field") or [])
                            g = groups.setdefault(key, [])
                            g.append((i, t, fl))
                            while g and t - g[0][1] > look:
                                g.pop(0)
                            if len(g) >= th["value"] and all(
                                    len({str(v) for _, _, y in g for v in y.get(c["field"]) or []}) >= c["value"] for c in th.get("cardinality") or []):
                                idx.update(j for j, _, _ in g)
                        fire(r, idx)
                    else:
                        raise RuntimeError(f"rule type {kind}")
                else:
                    raise RuntimeError(f"language {lang}")
            except NotApplicable as x:
                report["ran"] -= 1
                report["not_run"].setdefault("its index is not in the corpus", []).append(f"{r['name']} ({x})")
            except Exception as x:  # a rule that cannot be run is reported, not counted quiet
                report["failed"].append({"rule": r["name"], "type": kind, "language": lang, "error": f"{type(x).__name__}: {x}"[:400]})
            print(".", end="", file=sys.stderr, flush=True)
    n, missing = corpus.write(args[4], records, hits, args[5])
    json.dump(report, open(os.path.join(args[5], "rules.json"), "w"), indent=1)
    print(f"\n{report['ran']} rules run, {len(report['failed'])} failed, not run: { {k: len(v) for k, v in report['not_run'].items()} }; "
          f"{len(hits)} of {len(records)} records flagged at {level}+; {n} scored, {missing} not found", file=sys.stderr)


main()
