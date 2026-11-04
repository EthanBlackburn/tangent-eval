# Identity

Okta, Google Workspace and a product's own logins: impossible travel, an admin signing in from a hosting provider abroad, MFA turned off or reset and re-enrolled elsewhere, a burst of failures then a success, a key or a promotion used minutes later, SSO bypassed.

10 cases: 10 should flag, 0 must not. `P1` is the first corpus to pass; `P2` is next. Each case is a directory with `case.yaml` (what it is, and what the judge should say) and `events.ndjson` (its records, in the shape of the real source); [gen.py](../../gen.py) writes both.

| case | | sources | events | what the logs show |
|---|---|---|---|---|
| [`admin-login-new-asn`](admin-login-new-asn/) | flag P1 | `okta` | 5 | Admin console login from a hosting-provider ASN in a new country |
| [`api-key-admin-then-new-ip`](api-key-admin-then-new-ip/) | flag P1 | `app` | 3 | An admin-scoped API key is created at the office and first used from a VPS |
| [`impossible-travel`](impossible-travel/) | flag P1 | `okta` | 2 | Two successful logins, two continents, 22 minutes apart |
| [`mfa-disabled`](mfa-disabled/) | flag P1 | `okta` | 2 | Admin deactivates their own MFA factor, then signs in without it |
| [`mfa-reset-then-new-factor-new-asn`](mfa-reset-then-new-factor-new-asn/) | flag P1 | `okta`, `cloudtrail` | 11 | The helpdesk resets a person's MFA; a factor is enrolled and used from a new network |
| [`okta-failed-burst-then-success`](okta-failed-burst-then-success/) | flag P1 | `okta`, `app` | 20 | Twelve failed Okta sign-ins from one host, then one that works |
| [`okta-new-country-then-aws`](okta-new-country-then-aws/) | flag P1 | `okta`, `cloudtrail` | 11 | An Okta sign-in from a new country, then the same person's AWS console from another host |
| [`okta-new-country-then-github`](okta-new-country-then-github/) | flag P1 | `okta`, `github_audit` | 8 | An Okta sign-in from a new country, then the same person's GitHub token from another host |
| [`role-change-then-privileged-action`](role-change-then-privileged-action/) | flag P2 | `app` | 2 | A member is promoted to admin at night and exports the org minutes later |
| [`sso-bypass-password-login`](sso-bypass-password-login/) | flag P1 | `app` | 2 | Password login succeeds in an org with SSO enforced |

[All categories](../README.md)
