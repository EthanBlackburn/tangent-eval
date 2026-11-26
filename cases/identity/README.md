# Identity

Okta, Google Workspace, Supabase Auth and a product's own logins: impossible travel, an admin signing in from a hosting provider abroad, MFA turned off or reset and re-enrolled elsewhere, a burst of failures then a success, a key or a promotion used minutes later, SSO bypassed, a product's users' passwords stuffed, recovered or their second factor guessed.

19 cases: 19 should flag, 0 must not. `P1` is the first corpus to pass; `P2` is next. Each case is a directory with `case.yaml` (what it is, and what the judge should say) and `events.ndjson` (its records, in the shape of the real source); [gen.py](../../gen.py) writes both.

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
| [`supabase-credential-stuffing-then-in`](supabase-credential-stuffing-then-in/) | flag P1 | `supabase` | 244 | Hundreds of refused sign-ins to the product from hosting providers in seven minutes; then one works, and that user's email is changed |
| [`supabase-recovery-then-second-factor-removed`](supabase-recovery-then-second-factor-removed/) | flag P1 | `supabase` | 6 | A user's password is recovered from a hosting provider abroad; the session then removes their second factor and changes the email |
| [`supabase-refresh-token-used-from-two-countries`](supabase-refresh-token-used-from-two-countries/) | flag P1 | `supabase` | 9 | One user's session is refreshed in turn from their home in the UK and from a hosting provider in Singapore, until the token is revoked for reuse |
| [`supabase-second-factor-guessed`](supabase-second-factor-guessed/) | flag P1 | `supabase` | 184 | A user's password works from a hosting provider, and their TOTP code is tried 180 times in ten minutes until one is accepted |
| [`supabase-signups-from-one-hosting-network`](supabase-signups-from-one-hosting-network/) | flag P2 | `supabase` | 120 | Sixty accounts are made in four minutes from one hosting provider's network, each with a random name at a throwaway mail domain |
| [`workspace-domain-wide-delegation-new-admin`](workspace-domain-wide-delegation-new-admin/) | flag P1 | `google_workspace` | 4 | The admin's session, from a hosting provider, gives an API client the whole domain's mail and Drive, then makes a second super admin |
| [`workspace-helpdesk-reset-then-new-network`](workspace-helpdesk-reset-then-new-network/) | flag P1 | `google_workspace` | 11 | The admin resets the CFO's password and turns off her 2-step verification; she signs in from a hosting provider and downloads the finance documents |
| [`workspace-oauth-consent-then-token-abroad`](workspace-oauth-consent-then-token-abroad/) | flag P1 | `google_workspace` | 18 | A person grants an unknown app their mail and Drive; minutes later the app's token reads both from a hosting provider |
| [`workspace-recovery-swap-then-downloads`](workspace-recovery-swap-then-downloads/) | flag P1 | `google_workspace` | 13 | A sign-in from a new country changes the recovery address and phone, turns off 2-step verification and the password, then downloads |

[All categories](../README.md)
