# Supply chain

CI and dependencies: an Action's tags moved to a stealer, a postinstall that phones home, a typosquat, worms that publish credentials as repositories, a backdoored PyPI release, a trojaned axios.

8 cases: 8 should flag, 0 must not. `P1` is the first corpus to pass; `P2` is next. Each case is a directory with `case.yaml` (what it is, and what the judge should say) and `events.ndjson` (its records, in the shape of the real source); [gen.py](../../gen.py) writes both.

| case | | sources | events | what the logs show |
|---|---|---|---|---|
| [`action-prints-runner-memory`](action-prints-runner-memory/) | flag P1 | `gha_ci`, `cloudtrail` | 6 | A popular Action's tags are moved to a commit that prints the runner's memory, secrets included, into the job log (tj-actions/changed-files, March 2025) |
| [`ci-action-tags-retargeted`](ci-action-tags-retargeted/) | flag P1 | `gha_ci`, `runner_egress`, `cloudtrail` | 10 | A security scanner's Action has its version tags force-pushed to a stealer (TeamPCP: Trivy, KICS; March 2026) |
| [`ci-postinstall-egress`](ci-postinstall-egress/) | flag P1 | `gha_ci`, `runner_egress` | 6 | npm install runs a postinstall that talks to webhook.site from the build runner |
| [`new-dependency-typosquat`](new-dependency-typosquat/) | flag P2 | `github_audit`, `gha_ci` | 2 | A PR adds a two-day-old package whose name is one letter off a popular one |
| [`postinstall-ai-cli-inventory-then-repos-public`](postinstall-ai-cli-inventory-then-repos-public/) | flag P1 | `github_audit` | 18 | nx/s1ngularity: a postinstall drives the developer's AI CLIs to inventory secrets; days later the stolen token flips repos public (Aug 2025) |
| [`preinstall-worm-publishes-credentials-as-repos`](preinstall-worm-publishes-credentials-as-repos/) | flag P1 | `gha_ci`, `runner_egress`, `github_audit` | 10 | Shai-Hulud, second wave: a preinstall fetches Bun, hunts credentials and publishes them as repos with the runner's token (Nov 2025; again with valid provenance, Aug 2026) |
| [`pypi-package-pth-stealer`](pypi-package-pth-stealer/) | flag P1 | `gha_ci`, `runner_egress`, `cloudtrail` | 10 | A backdoored PyPI release runs on every Python start and ships the runner's credentials (LiteLLM 1.82.8, March 2026) |
| [`trojan-dependency-rat`](trojan-dependency-rat/) | flag P1 | `gha_ci`, `runner_egress`, `github_audit` | 14 | A hijacked maintainer account publishes axios with a new dependency whose postinstall drops a RAT (March 2026) |

[All categories](../README.md)
