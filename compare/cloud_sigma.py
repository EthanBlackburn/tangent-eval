"""Sigma's cloud rules (AWS CloudTrail, Okta, GitHub audit, Google Workspace) over the cloud corpus.

    python3 -I cloud_sigma.py STREAM RUN_VERDICTS OUT [--level medium]

sigma-cloud.json is the rules as JSON. A rule reads the records of its
service, by the field names the service's own log has (which the corpus
keeps); a field holding an object is read as its JSON. A record is flagged
when a rule of the level or higher fires on it. OUT/verdicts.ndjson is for
tangent-eval's score_v2.py; OUT/rules.json is each rule's count."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import corpus
from sigma import condition, selection

LEVELS = ["informational", "low", "medium", "high", "critical"]
SERVICE = {"cloudtrail": "cloudtrail", "okta": "okta", "github_audit": "audit"}


class Fields(dict):
    """A record by Sigma's dotted names, without regard to the case of a key."""

    def __init__(self, r):
        super().__init__()
        self.r = r

    def find(self, name):
        v = self.r
        for part in name.split("."):
            if isinstance(v, list):
                v = next((x for x in v if isinstance(x, dict)), None)
            if not isinstance(v, dict):
                return None
            k = next((k for k in v if k.lower() == part.lower()), None)
            if k is None:
                return None
            v = v[k]
        return v

    def __contains__(self, name):
        return self.find(name) is not None

    def __getitem__(self, name):
        v = self.find(name)
        return json.dumps(v) if isinstance(v, (dict, list)) else ("true" if v is True else "false" if v is False else v)

    def values(self):
        return [json.dumps(self.r)]


def workspace(r):
    """A Workspace activity by the names Sigma's rules use (the admin and login audit logs)."""
    e = (r.get("events") or [{}])[0]
    app = (r.get("id") or {}).get("applicationName") or ""
    out = {"eventService": f"{app}.googleapis.com", "eventName": e.get("name"),
           "protoPayload": {"serviceName": f"{app}.googleapis.com", "metadata": {"event": {"eventName": e.get("name")}}}}
    for p in e.get("parameters") or []:
        out[p["name"].lower()] = p.get("value", p.get("boolValue", p.get("multiValue")))
    return f"google_workspace.{app}", out


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    level = sys.argv[sys.argv.index("--level") + 1] if "--level" in sys.argv else "medium"
    records = corpus.stream(args[0])
    rules = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "sigma-cloud.json")))
    skipped = [r["title"] for r in rules if "fieldref" in json.dumps(r["detection"])]
    rules = [r for r in rules if r["title"] not in skipped]
    hits, counts = {}, {}
    for i, rec in enumerate(records):
        svc, f = (SERVICE.get(rec["source"]), rec) if rec["source"] != "google_workspace" else workspace(rec)
        if not svc:
            continue
        f = Fields(f)
        for r in rules:
            if r["logsource"].get("service") != svc:
                continue
            det = r["detection"]
            names = [k for k in det if k not in ("condition", "timeframe")]
            memo = {}

            def truth(n):
                if n not in memo:
                    memo[n] = selection(det[n], f)
                return memo[n]

            conds = det["condition"] if isinstance(det["condition"], list) else [det["condition"]]
            if any(condition(c, names, truth) for c in conds):
                c = counts.setdefault(r["title"], {"level": r.get("level"), "count": 0})
                c["count"] += 1
                if LEVELS.index(r.get("level") or "medium") >= LEVELS.index(level):
                    hits.setdefault(i, []).append(r["title"])
    n, missing = corpus.write(args[1], records, hits, args[2])
    json.dump({"rules": len(rules), "skipped": skipped, "fired": counts}, open(os.path.join(args[2], "rules.json"), "w"), indent=1)
    print(f"{len(rules)} rules, {len(skipped)} skipped; {len(hits)} of {len(records)} records flagged at {level}+; {n} scored, {missing} not found in the stream", file=sys.stderr)


main()
