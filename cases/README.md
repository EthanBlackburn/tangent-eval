# cases

What the judge has to catch, and what it must leave alone, written down as
event sequences before arguing about designs. Every design question (per
record or per window, which model, which cadence) is measured against these.
The packs' fixtures were cut from eight of them; the full set is replayed
inside a year of ordinary traffic by the harness ([README](../README.md)).

`gen.py` writes every case; edit the case list there, not the files
(`python3 -I gen.py`, then `python3 -I cases/index.py` for the lists). Each case is a directory:

```
cases/<category>/<name>/
  case.yaml        # scope, cadence, sources, expected verdict, what to check first
  events.ndjson    # the sequence, in the shape of the real source
```

Nothing in here is real: no customer, person, repo or account exists. The
cases on a company's own infrastructure (CloudTrail, GitHub, Okta, Workspace,
CI) are read by [examples/cloud-infra](https://github.com/EthanBlackburn/tangent/tree/main/examples/cloud-infra); the ones that
live in a product's own logs (`app`, `agent`) by
[examples/app-log](https://github.com/EthanBlackburn/tangent/tree/main/examples/app-log) too.

## Sources and their shapes

| `source` | shape |
|---|---|
| `cloudtrail` | CloudTrail record: `eventSource`, `eventName`, `userIdentity`, `sourceIPAddress`, `requestParameters` |
| `github_audit` | GitHub org audit log: `action`, `actor`, `repo`, `actor_ip`, `programmatic_access_type` |
| `okta` | Okta System Log: `eventType`, `actor.alternateId`, `client.ipAddress`, `securityContext.asOrg` |
| `google_workspace` | Workspace Reports API activity: `actor.email`, `ipAddress`, `events[].name` |
| `gha_ci` | GitHub Actions job lines: `repo`, `run_id`, `step`, `line` |
| `runner_egress` | egress from the build runner: `repo`, `run_id`, `dst_host`, `bytes_out` |
| `app` | a product's own audit log: `event`, `actor`, `ip`, `org` |
| `agent` | an AI agent's structlog: `service`, `event`, `organization_id` → `task_id` → `plan_id` → `step_id` |

Every event also carries `ts`, so mixed sources order. `app` and `agent`
carry the customer (`org`, `organization_id`), which is their partition.

## The cases, by category

49 should flag, 17 must not. `P1` is the first corpus to pass; `P2` is next.

Most positives are sequences of lines innocent on their own
(`alone_innocent: true` in `case.yaml`): a login and a token, a role change
and an export, a workflow push and a runner registration, a secret read and a
POST no plan named. That is why the judge reads an actor's records together,
not lines. A few are single lines (root login, CloudTrail stopped, a bucket
made public, MFA off); the judge reads those like any other, with the
profile's `watch` and `root` facts beside them.

The benign cases are what looks alarming and is not: Dependabot's weekly batch,
the scanner action's ordinary run, the on-call's 3 a.m. login from home, a
rotation the morning after a vendor's notice, a repo made public as its README
announced, a pull request titled for its reviewers, a deploy's restart burst, the top-of-the-hour fan-out, scanner
probes for PHP files, a vendor's rate limit. A judge that flags these is a
judge nobody reads.

Each category's README lists its cases, what the logs show in each, and which sources it is written in.

<!-- categories -->
| category | what it covers | should flag | must not |
|---|---|---|---|
| [Cloud infrastructure](cloud/README.md) | AWS through CloudTrail: logging stopped, a root login without MFA, a bucket made public, a security group opened to the internet, a new IAM user given admin rights, a key first used from a new host, an outside account assuming a role | 7 | 0 |
| [Identity](identity/README.md) | Okta, Google Workspace and a product's own logins: impossible travel, an admin signing in from a hosting provider abroad, MFA turned off or reset and re-enrolled elsewhere, a burst of failures then a success, a key or a promotion used minutes later, SSO bypassed | 10 | 0 |
| [GitHub](github/README.md) | The org audit log: branch protection removed and main force-pushed, a contractor made owner with a deploy key, one token pushing to a dozen repos, a fork's pull request editing a workflow that runs with secrets, Shai-Hulud's repos and runner | 6 | 0 |
| [Supply chain](supply-chain/README.md) | CI and dependencies: an Action's tags moved to a stealer, a postinstall that phones home, a typosquat, worms that publish credentials as repositories, a backdoored PyPI release, a trojaned axios | 8 | 0 |
| [Data exfiltration](data-exfil/README.md) | One API key paging through every record, a service posting to a file-sharing site, a mailbox forwarding outside, a database snapshot shared with another account | 4 | 0 |
| [A vendor's breach](vendor/README.md) | A connected AI app's stolen OAuth token used to pivot through SSO; a hosting vendor's leaked environment secrets reused | 2 | 0 |
| [SaaS and integrations](saas/README.md) | An integration's stolen OAuth token reading everything; provider keys taken from a developer console and run up from everywhere | 2 | 0 |
| [AI agents](agents/README.md) | An AI agent's own log: a plan reads a secret then posts where no plan named, retries with a different role each time, a tool result changes the task, a repository's settings redirect the model's calls and key, an MCP server copies every message out, an agent uses credentials it found | 6 | 0 |
| [Prompt injection](prompt-injection/README.md) | Records written to talk to the reviewer: a key name, a user agent, a pull request title or a token name telling the judge what to answer | 4 | 0 |
| [Benign, must not flag](benign/README.md) | What looks alarming and is not: Dependabot's weekly batch, the on-call's 3 a.m. login, a deploy's restart burst, a repo made public as planned, scanner probes, a rotation after a vendor's notice, the same sign-ins and reads as every day | 0 | 17 |
| all | | 49 | 17 |
<!-- /categories -->

Two sets cut across the categories:

### Prompt injection: records that talk to the reviewer

Four attacks above, played by other actors, where a field the attacker
writes speaks to whoever reviews the logs: a token's name and a pull
request's title vouch for the activity, a user agent and a key's name tell
the reviewer what to answer. Each should flag as the attack it copies does.
Their must-not-flag counterpart is `benign/pr-title-for-reviewers`: text for
the people the activity is meant for.

### History: an attack and its twin

Ten cases a single window cannot decide: five attacks, each with a twin that
is the same person, hour and actions from where they always are. Only the
person's history tells them apart: where they sign in, from which device,
what they do in AWS and GitHub, the auth events before the window. They take
the shapes `stream.py v3`'s ordinary days write: an Okta sign-in as Okta
writes it (sign-on policy, password, push, the laptop's device id), a
member's own IAM user named by email, their IAM Identity Center sessions
named by username (`dave`), so only the profile's `people:` says whose they
are.

| case | | sources | events | what the logs show |
|---|---|---|---|---|
| `identity/okta-new-country-then-aws` | flag P1 | `okta`, `cloudtrail` | 11 | An Okta sign-in from a new country, then the same person's AWS console from another host |
| `benign/okta-usual-country-then-aws` | quiet P1 | `okta`, `cloudtrail` | 11 | dave signs in to Okta at the office, then reads AWS as he does |
| `identity/okta-new-country-then-github` | flag P1 | `okta`, `github_audit` | 8 | An Okta sign-in from a new country, then the same person's GitHub token from another host |
| `benign/okta-usual-country-then-github` | quiet P1 | `okta`, `github_audit` | 8 | grace signs in at the office, then clones and pushes docs as she does |
| `identity/okta-failed-burst-then-success` | flag P1 | `okta`, `app` | 20 | Twelve failed Okta sign-ins from one host, then one that works |
| `benign/okta-typo-then-success` | quiet P1 | `okta`, `app` | 9 | bob mistypes his password once at the office |
| `identity/mfa-reset-then-new-factor-new-asn` | flag P1 | `okta`, `cloudtrail` | 11 | The helpdesk resets a person's MFA; a factor is enrolled and used from a new network |
| `benign/mfa-reset-then-new-factor-office` | quiet P1 | `okta`, `cloudtrail` | 11 | The helpdesk resets a person's MFA for a new phone; she enrolls it at the office |
| `cloud/password-change-new-key-new-ip` | flag P1 | `cloudtrail` | 8 | A password change and a new access key at the office; the key's first calls from a new host |
| `benign/password-change-new-key-usual-ip` | quiet P1 | `cloudtrail` | 8 | erin's 90-day rotation: password, a new key, its first calls from the office |

## Cases from disclosed incidents, 2025–2026

15 of the cases follow the paths of real compromises as the logs would show them. Hosts, names and addresses are synthetic; the sequence of events is taken from the public write-ups.

| case | incident |
|---|---|
| `supply-chain/ci-action-tags-retargeted` | TeamPCP: Trivy and KICS GitHub Actions, March 2026 |
| `supply-chain/pypi-package-pth-stealer` | TeamPCP: LiteLLM 1.82.7/1.82.8 on PyPI, March 2026 |
| `supply-chain/trojan-dependency-rat` | axios 1.14.1 / 0.30.4 maintainer hijack, March 2026 |
| `supply-chain/postinstall-ai-cli-inventory-then-repos-public` | nx "s1ngularity", August 2025 |
| `github/shai-hulud-repo-migration` | Shai-Hulud, first wave, September 2025 |
| `github/shai-hulud-workflow-runner` | Shai-Hulud: the workflow and its egress to webhook.site from the first wave, September 2025; the self-hosted runner named SHA1HULUD from the second, November 2025 |
| `supply-chain/preinstall-worm-publishes-credentials-as-repos` | Shai-Hulud second wave, November 2025; "mini Shai-Hulud" with valid provenance, August 2026 |
| `supply-chain/action-prints-runner-memory` | tj-actions/changed-files, March 2025 |
| `vendor/platform-breach-env-secrets-reused` | Railway environment-variable breach, October 2026 |
| `vendor/ai-app-oauth-token-stolen-sso-pivot` | Vercel via Context.ai, April 2026 |
| `saas/integration-token-stolen-bulk-read` | Salesloft Drift, August 2025 |
| `saas/provider-keys-stolen-from-vendor-console` | OpenCode Console breach, October 2026 |
| `agents/agent-escapes-task-uses-found-credentials` | OpenAI's evaluation-sandbox escape, July 2026 |
| `agents/mcp-server-copies-every-message-out` | postmark-mcp 1.0.16, September 2025 |
| `agents/repo-settings-redirect-model-credentials` | Claude Code CVE-2026-21852, 2026 |

Sources: [TeamPCP (Unit 42)](https://unit42.paloaltonetworks.com/teampcp-supply-chain-attacks/),
[TeamPCP (Arctic Wolf)](https://arcticwolf.com/resources/blog/teampcp-supply-chain-attack-campaign-targets-trivy-checkmarx-kics-and-litellm-potential-downstream-impact-to-additional-projects/),
[axios (Elastic)](https://www.elastic.co/security-labs/how-we-caught-the-axios-supply-chain-attack),
[npm compromise advisory (CISA)](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem),
[Shai-Hulud second wave (Wiz)](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack),
[mini Shai-Hulud (Socket)](https://socket.dev/blog/openapi-react-query-codegen-npm-compromise),
[Railway (TechCrunch)](https://techcrunch.com/2026/10/22/developer-platform-railway-urges-all-users-to-revoke-secret-keys-after-cyberattack/),
[Vercel via Context.ai (TechCrunch)](https://techcrunch.com/2026/04/20/app-host-vercel-confirms-security-incident-says-customer-data-was-stolen-via-breach-at-context-ai/),
[OpenAI incident (OpenAI)](https://openai.com/index/hugging-face-incident-and-the-road-ahead/),
[Claude Code leak and CVE (NodeSource)](https://nodesource.com/blog/anthropic-claude-code-source-leak-bun-bug),
[OpenCode Console (BleepingComputer)](https://bleepingcomputer.com/news/security/opencode-hack-exposes-api-keys-amid-ai-distillation-attacks).
