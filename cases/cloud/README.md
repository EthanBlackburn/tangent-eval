# Cloud infrastructure

AWS through CloudTrail: logging stopped, a root login without MFA, a bucket made public, a security group opened to the internet, a new IAM user given admin rights, a key first used from a new host, an outside account assuming a role.

7 cases: 7 should flag, 0 must not. `P1` is the first corpus to pass; `P2` is next. Each case is a directory with `case.yaml` (what it is, and what the judge should say) and `events.ndjson` (its records, in the shape of the real source); [gen.py](../../gen.py) writes both.

| case | | sources | events | what the logs show |
|---|---|---|---|---|
| [`assume-role-new-principal-then-reads`](assume-role-new-principal-then-reads/) | flag P2 | `cloudtrail` | 21 | An external account assumes the read-only role and reads customer exports |
| [`cloudtrail-stop-logging`](cloudtrail-stop-logging/) | flag P1 | `cloudtrail` | 1 | CloudTrail logging stopped |
| [`iam-key-create-attach-star-then-use`](iam-key-create-attach-star-then-use/) | flag P1 | `cloudtrail` | 5 | A new IAM user gets an access key and AdministratorAccess, then reads buckets from a new IP |
| [`password-change-new-key-new-ip`](password-change-new-key-new-ip/) | flag P1 | `cloudtrail` | 8 | A password change and a new access key at the office; the key's first calls from a new host |
| [`root-console-login`](root-console-login/) | flag P1 | `cloudtrail` | 1 | Root account console login without MFA |
| [`s3-bucket-public`](s3-bucket-public/) | flag P1 | `cloudtrail` | 2 | Public access block removed and a bucket policy grants everyone read |
| [`sg-open-world`](sg-open-world/) | flag P1 | `cloudtrail` | 1 | A security group opens Postgres to the internet |

[All categories](../README.md)
