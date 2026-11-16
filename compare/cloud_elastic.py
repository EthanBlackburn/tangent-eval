"""Elastic's cloud detection rules (AWS, Okta, GitHub, Google Workspace) over the cloud corpus.

    python3 -I cloud_elastic.py RULES STREAM TRUTH RUN_VERDICTS OUT [--level medium]

RULES is a checkout of elastic/detection-rules; the rules read are
rules/integrations/{aws,okta,github,google_workspace}, each over its own
source's records, mapped to the fields Elastic's integration for the source
indexes (ECS and `aws.cloudtrail.*`, `okta.*`, `github.*`, `google_workspace.*`).

  KQL          kql.py
  EQL          Elastic's `eql` package, with elastic.py's engine; every event type is read as `any`
  new terms    the query, and the rule's fields taking a value not seen in its history window.
               A case's records are not in another case's history, as in tangent's runs.
  threshold    the query, and the count (and cardinality) reached within the rule's lookback

ES|QL and machine-learning rules are not run; OUT/rules.json lists them. A
record is flagged when a rule of the level or higher fires on it (every event
of an EQL sequence, every record of a threshold's window)."""
import glob
import ipaddress
import json
import os
import re
import sys
import tomllib
from datetime import datetime

import eql

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import corpus
import kql
from elastic import Engine

class Cloud(Engine):
    """`stringContains` with a `*` in what it looks for: two of Elastic's AWS rules write one
    (`valuesToAdd=[*]`, `Principal=\\*`), which read to the letter could not match a CloudTrail record.
    Here a bare `*` is any text and `\\*` the character, the reading that lets the rules fire."""

    def _convert_function_call(self, node):
        if node.name == "stringContains" and isinstance(node.arguments[1], eql.ast.String) and "*" in node.arguments[1].value:
            parts = re.split(r"(\\\*|\*)", node.arguments[1].value.lower())
            pattern = re.compile("".join(".*" if p == "*" else re.escape("*" if p == "\\*" else p) for p in parts), re.S)
            get = self.convert(node.arguments[0])
            return lambda scope: isinstance(v := get(scope), str) and pattern.search(v.lower()) is not None
        return super()._convert_function_call(node)


LEVELS = ["low", "medium", "high", "critical"]
DIRS = {"cloudtrail": "aws", "okta": "okta", "github_audit": "github", "google_workspace": "google_workspace"}


def snake(k):
    return re.sub(r"(?<=[a-z0-9])([A-Z])", r"_\1", k).lower()


def snaked(v):
    if isinstance(v, dict):
        return {snake(k): snaked(x) for k, x in v.items()}
    return [snaked(x) for x in v] if isinstance(v, list) else v


def javamap(v):
    """An object as Elastic's CloudTrail pipeline writes request_parameters: `{key=value, list=[a, b]}`."""
    if isinstance(v, dict):
        return "{" + ", ".join(f"{k}={javamap(x)}" for k, x in v.items()) + "}"
    if isinstance(v, list):
        return "[" + ", ".join(javamap(x) for x in v) + "]"
    return "true" if v is True else "false" if v is False else "null" if v is None else str(v)


def ip(s):
    try:
        ipaddress.ip_address(s)
        return s
    except (ValueError, TypeError):
        return None


def cloudtrail(r):
    u = r.get("userIdentity") or {}
    sc = u.get("sessionContext") or {}
    issuer = sc.get("sessionIssuer") or {}
    ct = {"event_version": r.get("eventVersion"), "event_type": r.get("eventType"), "event_category": r.get("eventCategory"),
          "error_code": r.get("errorCode"), "error_message": r.get("errorMessage"), "request_id": r.get("requestID"),
          "read_only": r.get("readOnly"), "management_event": r.get("managementEvent"), "recipient_account_id": r.get("recipientAccountId"),
          "session_credential_from_console": r.get("sessionCredentialFromConsole"), "vpc_endpoint_id": r.get("vpcEndpointId"),
          "user_identity": {"type": u.get("type"), "arn": u.get("arn"), "principal_id": u.get("principalId"), "account_id": u.get("accountId"),
                            "access_key_id": u.get("accessKeyId"), "invoked_by": u.get("invokedBy"),
                            "session_context": {"mfa_authenticated": (sc.get("attributes") or {}).get("mfaAuthenticated"),
                                                "creation_date": (sc.get("attributes") or {}).get("creationDate"),
                                                "session_issuer": snaked(issuer)}},
          "resources": [{"arn": x.get("ARN"), "account_id": x.get("accountId"), "type": x.get("type")} for x in r.get("resources") or []],
          "flattened": {}}
    for raw, name in (("requestParameters", "request_parameters"), ("responseElements", "response_elements"),
                      ("additionalEventData", "additional_eventdata"), ("serviceEventDetails", "service_event_details")):
        if r.get(raw) is not None:
            ct[name] = javamap(r[raw])
            ct["flattened"][name] = r[raw]
    add = r.get("additionalEventData") or {}
    if r.get("eventName") == "ConsoleLogin":
        ct["console_login"] = {"additional_eventdata": {"mfa_used": str(add.get("MFAUsed")).lower() == "yes",
                                                        "mobile_version": str(add.get("MobileVersion")).lower() == "yes", "login_to": add.get("LoginTo")}}
    name = u.get("userName") or issuer.get("userName") or ("root" if u.get("type") == "Root" else None)
    target = (r.get("requestParameters") or {}).get("userName") if isinstance(r.get("requestParameters"), dict) else None
    return {"data_stream": {"dataset": "aws.cloudtrail"}, "event": {
        "dataset": "aws.cloudtrail", "module": "aws", "kind": "event", "provider": r.get("eventSource"), "action": r.get("eventName"),
        "outcome": "failure" if r.get("errorCode") else "success", "id": r.get("eventID")},
        "cloud": {"provider": "aws", "region": r.get("awsRegion"), "account": {"id": r.get("recipientAccountId") or u.get("accountId")}},
        "user": {"name": name, "id": u.get("principalId"), "target": {"name": target}}, "user_agent": {"original": r.get("userAgent")},
        "source": {"address": r.get("sourceIPAddress"), "ip": ip(r.get("sourceIPAddress"))},
        "tls": {"version": (r.get("tlsDetails") or {}).get("tlsVersion")}, "aws": {"cloudtrail": ct}}


def okta(r):
    o = snaked({k: v for k, v in r.items() if k not in ("ts", "source")})
    c = r.get("client") or {}
    geo = c.get("geographicalContext") or {}
    sec = r.get("securityContext") or {}
    o["client"] = dict(o.get("client") or {}, ip=c.get("ipAddress"))
    dd = (r.get("debugContext") or {}).get("debugData") or {}
    o.setdefault("debug_context", {})["debug_data"] = dict(snaked(dd), flattened=dd)
    result = ((r.get("outcome") or {}).get("result") or "").lower()
    actor = r.get("actor") or {}
    targets = [t for t in r.get("target") or [] if isinstance(t, dict)]
    return {"data_stream": {"dataset": "okta.system"}, "event": {
        "dataset": "okta.system", "module": "okta", "kind": "event", "action": r.get("eventType"), "id": r.get("uuid"),
        "outcome": {"success": "success", "allow": "success", "failure": "failure", "deny": "failure"}.get(result, result or None)},
        "okta": o, "source": {"ip": ip(c.get("ipAddress")), "as": {"number": sec.get("asNumber"), "organization": {"name": sec.get("asOrg")}},
                              "geo": {"country_name": geo.get("country"), "city_name": geo.get("city"), "region_name": geo.get("state")},
                              "user": {"name": actor.get("alternateId"), "full_name": actor.get("displayName")}},
        "client": {"ip": ip(c.get("ipAddress")), "geo": {"country_name": geo.get("country"), "city_name": geo.get("city")},
                   "user": {"name": actor.get("alternateId")}},
        "user": {"name": actor.get("alternateId"), "email": actor.get("alternateId"),
                 "target": {"name": next((t.get("alternateId") for t in targets if t.get("type") == "User"), None)}},
        "user_agent": {"original": (c.get("userAgent") or {}).get("rawUserAgent")}}


def github(r):
    g = {k: v for k, v in r.items() if k not in ("ts", "source", "@timestamp")}
    g["category"] = (r.get("action") or "").split(".")[0]
    return {"data_stream": {"dataset": "github.audit"}, "event": {"dataset": "github.audit", "module": "github", "kind": "event",
                                                                 "action": r.get("action"), "type": ["change"]},
            "github": g, "user": {"name": r.get("actor")}, "source": {"ip": ip(r.get("actor_ip"))},
            # GitHub's audit log names the client on every event and the corpus does not: one stand-in,
            # so a rule that asks whether the client is new reads the field as it would
            "user_agent": {"original": r.get("user_agent") or ("git/2.45.0" if (r.get("action") or "").startswith("git.") else "Mozilla/5.0")},
            "geo": {"country_iso_code": (r.get("actor_location") or {}).get("country_code")}}


ADMIN = {"SETTING_NAME": ("setting", "name"), "NEW_VALUE": ("new_value",), "OLD_VALUE": ("old_value",), "APPLICATION_NAME": ("application", "name"),
         "ROLE_NAME": ("role", "name"), "PRIVILEGE_NAME": ("privilege", "name"), "USER_EMAIL": ("user", "email"), "DOMAIN_NAME": ("domain", "name"),
         "GROUP_EMAIL": ("group", "email"), "ORG_UNIT_NAME": ("org_unit", "name"), "APP_NAME": ("application", "name")}


def workspace(r):
    e = (r.get("events") or [{}])[0]
    app = (r.get("id") or {}).get("applicationName") or ""
    mine = {}
    for p in e.get("parameters") or []:
        v = p.get("value", p.get("boolValue", p.get("multiValue", p.get("intValue"))))
        at = ADMIN.get(p["name"]) if app == "admin" else None
        d = mine
        for part in (at or (snake(p["name"]),))[:-1]:
            d = d.setdefault(part, {})
        d[(at or (snake(p["name"]),))[-1]] = v
    actor = r.get("actor") or {}
    return {"data_stream": {"dataset": f"google_workspace.{app}"}, "event": {
        "dataset": f"google_workspace.{app}", "module": "google_workspace", "kind": "event", "provider": app, "action": e.get("name"),
        "id": (r.get("id") or {}).get("uniqueQualifier")},
        "google_workspace": {"event": {"type": e.get("type"), "name": e.get("name")}, "actor": {"type": actor.get("callerType"), "email": actor.get("email")},
                             app: mine, "kind": r.get("kind")},
        "user": {"email": actor.get("email"), "name": (actor.get("email") or "").split("@")[0], "domain": (actor.get("email") or "@").split("@")[1]},
        "source": {"ip": ip(r.get("ipAddress")), "user": {"email": actor.get("email")}}}


MAP = {"cloudtrail": cloudtrail, "okta": okta, "github_audit": github, "google_workspace": workspace}


def prune(v):
    if isinstance(v, dict):
        out = {k: p for k, x in v.items() if (p := prune(x)) not in (None, {}, [])}
        return out
    return [prune(x) for x in v] if isinstance(v, list) else v


def ms(t):
    return int(datetime.fromisoformat(t.replace("Z", "+00:00")).timestamp() * 1000)


def span(text, default):
    m = re.fullmatch(r"now-(\d+)([smhdw])", text or "")
    return int(m[1]) * {"s": 1000, "m": 60000, "h": 3600000, "d": 86400000, "w": 604800000}[m[2]] if m else default


def main():
    args = [a for k, a in enumerate(sys.argv) if k and not a.startswith("--") and sys.argv[k - 1] not in ("--level", "--without")]
    level = sys.argv[sys.argv.index("--level") + 1] if "--level" in sys.argv else "medium"
    root, records, truth = args[0], corpus.stream(args[1]), json.load(open(args[2]))
    case_of = {i: c["id"] for c in truth for i, *_ in c["rows"]}
    docs = {src: [(i, ms(r["ts"]), prune(MAP[src](r))) for i, r in enumerate(records) if r["source"] == src] for src in MAP}
    hits, report = {}, {"fired": {}, "not_run": {}, "failed": []}

    def fire(r, idx):
        c = report["fired"].setdefault(r["name"], {"severity": r["severity"], "type": r["type"], "count": 0})
        c["count"] += len(idx)
        if LEVELS.index(r["severity"]) >= LEVELS.index(level):
            for i in idx:
                hits.setdefault(i, []).append(r["name"])

    without = [sys.argv[k + 1] for k, a in enumerate(sys.argv) if a == "--without"]  # a rule left out, by name
    ran = 0
    for src, d in DIRS.items():
        mine = docs[src]
        for f in sorted(glob.glob(os.path.join(root, "rules/integrations", d, "*.toml"))):
            doc = tomllib.load(open(f, "rb"))
            r = doc["rule"]
            if doc["metadata"].get("maturity") == "deprecated" or r["name"] in without:
                continue
            kind = r["type"]
            if kind in ("esql", "machine_learning") or r.get("language") not in ("kuery", "eql"):
                report["not_run"].setdefault(kind, []).append(r["name"])
                continue
            ran += 1
            try:
                if kind == "eql":
                    text = re.sub(r"(^|\[)(\s*)[a-z_]+(\s+where\b)", r"\1\2any\3", r["query"], flags=re.M)
                    with eql.parser.elasticsearch_syntax, eql.parser.ignore_missing_functions, eql.parser.allow_sample, eql.parser.allow_runs:
                        q = eql.parse_query(text)
                    engine, got = Cloud(), []
                    engine.add_query(q)
                    engine.add_output_hook(got.append)
                    engine.stream_events(eql.Event("generic", t * 10000, dict(x, _i=i)) for i, t, x in mine)
                    idx = sorted({e.data["_i"] for g in got for e in g.events})
                    if idx:
                        fire(r, idx)
                    continue
                match = kql.compile(r["query"])
                matched = [(i, t, x) for i, t, x in mine if match(x)]
                if kind == "query":
                    idx = [i for i, _, _ in matched]
                elif kind == "new_terms":
                    nt = r["new_terms"]
                    fields = nt["value"]
                    window = span(nt["history_window_start"][0]["value"], 7 * 86400000)
                    last, idx = {}, []
                    for i, t, x in matched:
                        vals = [kql.values(x, f) for f in fields]
                        if not all(vals):
                            continue
                        key = tuple(str(v[0]) for v in vals)
                        case = case_of.get(i)
                        seen = [last.get((None, key))] + ([last.get((case, key))] if case else [])
                        if not any(s is not None and t - s <= window for s in seen):
                            idx.append(i)
                        last[(case, key)] = t
                elif kind == "threshold":
                    th = r["threshold"]
                    look = span(r.get("from"), 360000)
                    groups, idx = {}, set()
                    for i, t, x in matched:
                        key = tuple(str((kql.values(x, f) or [None])[0]) for f in th.get("field") or [])
                        g = groups.setdefault(key, [])
                        g.append((i, t, x))
                        while g and t - g[0][1] > look:
                            g.pop(0)
                        if len(g) >= th["value"] and all(
                                len({str(v) for _, _, y in g for v in kql.values(y, c["field"])}) >= c["value"] for c in th.get("cardinality") or []):
                            idx.update(j for j, _, _ in g)
                    idx = sorted(idx)
                else:
                    report["not_run"].setdefault(kind, []).append(r["name"])
                    ran -= 1
                    continue
                if idx:
                    fire(r, idx)
            except Exception as x:  # a rule that cannot be read or run is reported, not counted quiet
                report["failed"].append({"rule": r["name"], "type": kind, "error": f"{type(x).__name__}: {x}"[:200]})
    n, missing = corpus.write(args[3], records, hits, args[4])
    report["ran"] = ran
    json.dump(report, open(os.path.join(args[4], "rules.json"), "w"), indent=1)
    print(f"{ran} rules run, {len(report['failed'])} failed, not run: { {k: len(v) for k, v in report['not_run'].items()} }; "
          f"{len(hits)} of {len(records)} records flagged at {level}+; {n} scored, {missing} not found", file=sys.stderr)


if __name__ == "__main__":
    main()
