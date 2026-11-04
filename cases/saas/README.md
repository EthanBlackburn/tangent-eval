# SaaS and integrations

An integration's stolen OAuth token reading everything; provider keys taken from a developer console and run up from everywhere.

2 cases: 2 should flag, 0 must not. `P1` is the first corpus to pass; `P2` is next. Each case is a directory with `case.yaml` (what it is, and what the judge should say) and `events.ndjson` (its records, in the shape of the real source); [gen.py](../../gen.py) writes both.

| case | | sources | events | what the logs show |
|---|---|---|---|---|
| [`integration-token-stolen-bulk-read`](integration-token-stolen-bulk-read/) | flag P1 | `app` | 41 | A SaaS integration's OAuth token is stolen in the vendor's breach and used to read everything (Salesloft Drift, Aug 2025) |
| [`provider-keys-stolen-from-vendor-console`](provider-keys-stolen-from-vendor-console/) | flag P2 | `app` | 40 | Keys saved in a third-party developer console are taken in its breach and run up usage from everywhere (OpenCode Console, Oct 2026) |

[All categories](../README.md)
