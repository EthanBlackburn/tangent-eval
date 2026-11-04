# AI agents

An AI agent's own log: a plan reads a secret then posts where no plan named, retries with a different role each time, a tool result changes the task, a repository's settings redirect the model's calls and key, an MCP server copies every message out, an agent uses credentials it found.

6 cases: 6 should flag, 0 must not. `P1` is the first corpus to pass; `P2` is next. Each case is a directory with `case.yaml` (what it is, and what the judge should say) and `events.ndjson` (its records, in the shape of the real source); [gen.py](../../gen.py) writes both.

| case | | sources | events | what the logs show |
|---|---|---|---|---|
| [`agent-escapes-task-uses-found-credentials`](agent-escapes-task-uses-found-credentials/) | flag P1 | `agent`, `cloudtrail` | 14 | An agent given one credential finds more and uses them across services in minutes (OpenAI's evaluation-sandbox escape, July 2026) |
| [`mcp-server-copies-every-message-out`](mcp-server-copies-every-message-out/) | flag P1 | `agent` | 11 | A malicious MCP server release sends a copy of everything it handles to its author (postmark-mcp 1.0.16, Sept 2025) |
| [`plan-retry-shifting-params`](plan-retry-shifting-params/) | flag P2 | `agent` | 7 | A plan step fails and retries six times with a different role ARN each time |
| [`plan-secret-then-unplanned-post`](plan-secret-then-unplanned-post/) | flag P1 | `agent` | 6 | A plan step reads a secret, a later step POSTs to a host not in the plan |
| [`repo-settings-redirect-model-credentials`](repo-settings-redirect-model-credentials/) | flag P1 | `agent` | 6 | A cloned repository's assistant settings point the agent's model calls, API key included, at an attacker host (Claude Code CVE-2026-21852) |
| [`tool-output-injection-then-scope-change`](tool-output-injection-then-scope-change/) | flag P1 | `agent` | 5 | A tool result contains instructions; the next step acts on a different resource |

[All categories](../README.md)
