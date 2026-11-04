# Benign, must not flag

What looks alarming and is not: Dependabot's weekly batch, the on-call's 3 a.m. login, a deploy's restart burst, a repo made public as planned, scanner probes, a rotation after a vendor's notice, the same sign-ins and reads as every day.

17 cases: 0 should flag, 17 must not. `P1` is the first corpus to pass; `P2` is next. Each case is a directory with `case.yaml` (what it is, and what the judge should say) and `events.ndjson` (its records, in the shape of the real source); [gen.py](../../gen.py) writes both.

| case | | sources | events | what the logs show |
|---|---|---|---|---|
| [`admin-usual-ip-then-export`](admin-usual-ip-then-export/) | must not flag | `app` | 3 | An admin at the usual IP exports their own org's report |
| [`dependabot-bumps-axios`](dependabot-bumps-axios/) | must not flag | `github_audit`, `gha_ci`, `runner_egress` | 5 | Dependabot bumps axios to a clean release and CI runs it |
| [`dependabot-prs`](dependabot-prs/) | must not flag | `github_audit` | 10 | Dependabot opens its weekly batch of PRs and CI runs them |
| [`deploy-restart-burst`](deploy-restart-burst/) | must not flag | `agent` | 42 | A deploy: new version, forty health checks, a few restarts |
| [`mfa-reset-then-new-factor-office`](mfa-reset-then-new-factor-office/) | must not flag | `okta`, `cloudtrail` | 11 | The helpdesk resets a person's MFA for a new phone; she enrolls it at the office |
| [`okta-typo-then-success`](okta-typo-then-success/) | must not flag | `okta`, `app` | 9 | bob mistypes his password once at the office |
| [`okta-usual-country-then-aws`](okta-usual-country-then-aws/) | must not flag | `okta`, `cloudtrail` | 11 | dave signs in to Okta at the office, then reads AWS as he does |
| [`okta-usual-country-then-github`](okta-usual-country-then-github/) | must not flag | `okta`, `github_audit` | 8 | grace signs in at the office, then clones and pushes docs as she does |
| [`oncall-3am-login`](oncall-3am-login/) | must not flag | `okta`, `app` | 5 | The on-call engineer signs in at 3 a.m. from home, as every time they are paged |
| [`password-change-new-key-usual-ip`](password-change-new-key-usual-ip/) | must not flag | `cloudtrail` | 8 | erin's 90-day rotation: password, a new key, its first calls from the office |
| [`pr-title-for-reviewers`](pr-title-for-reviewers/) | must not flag | `github_audit` | 3 | A docs pull request whose title tells its reviewers it is safe to approve |
| [`repo-made-public-as-planned`](repo-made-public-as-planned/) | must not flag | `github_audit` | 2 | An admin makes the docs repo public, as the README it pushed first announces |
| [`scanner-action-usual-run`](scanner-action-usual-run/) | must not flag | `gha_ci`, `runner_egress` | 5 | The image scan step runs as it does on every build |
| [`scanner-probes`](scanner-probes/) | must not flag | `agent` | 5 | Internet scanners probe the public API for PHP and WordPress files |
| [`secret-rotation-after-vendor-notice`](secret-rotation-after-vendor-notice/) | must not flag | `cloudtrail`, `app` | 10 | Admins rotate keys the morning after a vendor's breach notice |
| [`top-of-hour-sync-fanout`](top-of-hour-sync-fanout/) | must not flag | `agent` | 60 | The poller fans out to GitHub at the top of the hour |
| [`vendor-429-burst`](vendor-429-burst/) | must not flag | `agent` | 9 | Okta rate-limits the poller, which backs off and succeeds |

[All categories](../README.md)
