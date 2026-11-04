# Data exfiltration

One API key paging through every record, a service posting to a file-sharing site, a mailbox forwarding outside, a database snapshot shared with another account.

4 cases: 4 should flag, 0 must not. `P1` is the first corpus to pass; `P2` is next. Each case is a directory with `case.yaml` (what it is, and what the judge should say) and `events.ndjson` (its records, in the shape of the real source); [gen.py](../../gen.py) writes both.

| case | | sources | events | what the logs show |
|---|---|---|---|---|
| [`bulk-pagination-export`](bulk-pagination-export/) | flag P1 | `app` | 40 | One API key pages through every finding in four minutes |
| [`egress-new-destination`](egress-new-destination/) | flag P2 | `agent` | 4 | A service that only talks to vendors posts to a file-sharing site |
| [`gmail-forwarding-rule`](gmail-forwarding-rule/) | flag P1 | `google_workspace` | 1 | Finance user's mailbox starts forwarding to an outside Gmail address |
| [`snapshot-shared-external`](snapshot-shared-external/) | flag P1 | `cloudtrail` | 1 | An RDS snapshot is shared with another AWS account |

[All categories](../README.md)
