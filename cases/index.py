#!/usr/bin/env python3
"""The case lists a reader browses: one README per category, and the
category table in cases/README.md, written from gen.py's cases so they
never drift from them.

    python3 -I cases/index.py           # rewrites cases/<category>/README.md and the table in cases/README.md

Each category README lists its cases: the case, whether it should flag and
its priority, the sources it is written in, how many events, and the title,
which says what the logs show. cases/README.md gets the table between its
`<!-- categories -->` markers: each category, what it covers (CATEGORIES
below), how many should flag and must not, with a link to its README.
Run it after gen.py."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import gen  # noqa: E402  (builds gen.CASES on import)

# Each category, in the order the table shows them: a heading, and what a
# reader should understand it covers, in one line.
CATEGORIES = {
    "cloud": ("Cloud infrastructure", "AWS through CloudTrail: logging stopped, a root login without MFA, a bucket made public, a security group opened to the internet, a new IAM user given admin rights, a key first used from a new host, an outside account assuming a role"),
    "identity": ("Identity", "Okta, Google Workspace and a product's own logins: impossible travel, an admin signing in from a hosting provider abroad, MFA turned off or reset and re-enrolled elsewhere, a burst of failures then a success, a key or a promotion used minutes later, SSO bypassed"),
    "github": ("GitHub", "The org audit log: branch protection removed and main force-pushed, a contractor made owner with a deploy key, one token pushing to a dozen repos, a fork's pull request editing a workflow that runs with secrets, Shai-Hulud's repos and runner"),
    "supply-chain": ("Supply chain", "CI and dependencies: an Action's tags moved to a stealer, a postinstall that phones home, a typosquat, worms that publish credentials as repositories, a backdoored PyPI release, a trojaned axios"),
    "data-exfil": ("Data exfiltration", "One API key paging through every record, a service posting to a file-sharing site, a mailbox forwarding outside, a database snapshot shared with another account"),
    "vendor": ("A vendor's breach", "A connected AI app's stolen OAuth token used to pivot through SSO; a hosting vendor's leaked environment secrets reused"),
    "saas": ("SaaS and integrations", "An integration's stolen OAuth token reading everything; provider keys taken from a developer console and run up from everywhere"),
    "agents": ("AI agents", "An AI agent's own log: a plan reads a secret then posts where no plan named, retries with a different role each time, a tool result changes the task, a repository's settings redirect the model's calls and key, an MCP server copies every message out, an agent uses credentials it found"),
    "prompt-injection": ("Prompt injection", "Records written to talk to the reviewer: a key name, a user agent, a pull request title or a token name telling the judge what to answer"),
    "benign": ("Benign, must not flag", "What looks alarming and is not: Dependabot's weekly batch, the on-call's 3 a.m. login, a deploy's restart burst, a repo made public as planned, scanner probes, a rotation after a vendor's notice, the same sign-ins and reads as every day"),
}


def category_readme(heading, about, rows):
    flag = sum(1 for c in rows if c["expected"]["flag"])
    lines = [f"# {heading}", "", about + ".", "",
             f"{len(rows)} cases: {flag} should flag, {len(rows) - flag} must not. `P1` is the first corpus to pass; `P2` is next. "
             "Each case is a directory with `case.yaml` (what it is, and what the judge should say) and `events.ndjson` "
             "(its records, in the shape of the real source); [gen.py](../../gen.py) writes both.", "",
             "| case | | sources | events | what the logs show |", "|---|---|---|---|---|"]
    for c in rows:
        verdict = f"flag {c['priority']}" if c["expected"]["flag"] else "must not flag"
        name = c["id"].split("/", 1)[1]
        sources = ", ".join(f"`{s}`" for s in c["sources"])
        lines.append(f"| [`{name}`]({name}/) | {verdict} | {sources} | {len(c['events'])} | {c['title']} |")
    lines += ["", "[All categories](../README.md)", ""]
    return "\n".join(lines)


def main():
    by = {}
    for c in gen.CASES:  # by directory: the github cases' `category` is supply-chain
        by.setdefault(c["id"].split("/", 1)[0], []).append(c)
    unknown = sorted(set(by) - set(CATEGORIES))
    if unknown:
        sys.exit(f"categories not in CATEGORIES: {', '.join(unknown)}")
    table = ["| category | what it covers | should flag | must not |", "|---|---|---|---|"]
    total = [0, 0]
    for category, (heading, about) in CATEGORIES.items():
        rows = sorted(by.get(category, []), key=lambda c: c["id"])
        if not rows:
            sys.exit(f"{category}: no cases")
        with open(os.path.join(HERE, category, "README.md"), "w") as f:
            f.write(category_readme(heading, about, rows))
        flag = sum(1 for c in rows if c["expected"]["flag"])
        total[0] += flag
        total[1] += len(rows) - flag
        table.append(f"| [{heading}]({category}/README.md) | {about} | {flag} | {len(rows) - flag} |")
    table.append(f"| all | | {total[0]} | {total[1]} |")
    # The same table in cases/README.md and, with its links from the root, in README.md
    for path, prefix in ((os.path.join(HERE, "README.md"), ""), (os.path.join(os.path.dirname(HERE), "README.md"), "cases/")):
        text = open(path).read()
        start, end = "<!-- categories -->", "<!-- /categories -->"
        a, b = text.index(start) + len(start), text.index(end)
        rows = [r.replace("](", f"]({prefix}") if r.startswith("| [") else r for r in table]
        with open(path, "w") as f:
            f.write(text[:a] + "\n" + "\n".join(rows) + "\n" + text[b:])
    print(f"{total[0]} should flag, {total[1]} must not, in {len(CATEGORIES)} categories")


if __name__ == "__main__":
    main()
