# A vendor's breach

A connected AI app's stolen OAuth token used to pivot through SSO; a hosting vendor's leaked environment secrets reused.

2 cases: 2 should flag, 0 must not. `P1` is the first corpus to pass; `P2` is next. Each case is a directory with `case.yaml` (what it is, and what the judge should say) and `events.ndjson` (its records, in the shape of the real source); [gen.py](../../gen.py) writes both.

| case | | sources | events | what the logs show |
|---|---|---|---|---|
| [`ai-app-oauth-token-stolen-sso-pivot`](ai-app-oauth-token-stolen-sso-pivot/) | flag P1 | `google_workspace`, `okta`, `app` | 18 | An AI productivity app an employee connected to her Google account is breached; its OAuth token reads her Drive, then her SSO opens the internal tools (Vercel via Context.ai, April 2026) |
| [`platform-breach-env-secrets-reused`](platform-breach-env-secrets-reused/) | flag P1 | `cloudtrail`, `github_audit`, `app` | 24 | A hosting vendor's breach exposes stored environment variables; what was in them is used from a datacenter within a day (Railway, Oct 2026) |

[All categories](../README.md)
