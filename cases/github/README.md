# GitHub

The org audit log: branch protection removed and main force-pushed, a contractor made owner with a deploy key, one token pushing to a dozen repos, a fork's pull request editing a workflow that runs with secrets, Shai-Hulud's repos and runner.

6 cases: 6 should flag, 0 must not. `P1` is the first corpus to pass; `P2` is next. Each case is a directory with `case.yaml` (what it is, and what the judge should say) and `events.ndjson` (its records, in the shape of the real source); [gen.py](../../gen.py) writes both.

| case | | sources | events | what the logs show |
|---|---|---|---|---|
| [`branch-protection-off-force-push`](branch-protection-off-force-push/) | flag P1 | `github_audit` | 3 | Branch protection removed, main force-pushed, protection restored |
| [`new-owner-and-deploy-key`](new-owner-and-deploy-key/) | flag P2 | `github_audit` | 2 | A contractor becomes org owner and adds a read-write deploy key |
| [`pat-mass-push`](pat-mass-push/) | flag P1 | `github_audit` | 12 | One personal access token pushes to a dozen repos in three minutes |
| [`pwn-request-workflow-from-fork`](pwn-request-workflow-from-fork/) | flag P2 | `github_audit` | 2 | A PR from a fork edits a workflow that runs with secrets |
| [`shai-hulud-repo-migration`](shai-hulud-repo-migration/) | flag P1 | `github_audit` | 4 | Shai-Hulud: a repo named Shai-Hulud appears, a private repo goes public as -migration |
| [`shai-hulud-workflow-runner`](shai-hulud-workflow-runner/) | flag P1 | `github_audit`, `runner_egress` | 4 | Shai-Hulud: a workflow file pushed straight to main, a runner registered, egress to webhook.site |

[All categories](../README.md)
