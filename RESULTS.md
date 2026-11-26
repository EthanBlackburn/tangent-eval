# Results

## This layout

**2026-11-15, one run.** The corpus as `make corpus` writes it: the 188
cases with a record in a source the packs read, 198 judged windows, arm
`isolated`. tangent at `0044b6e`, with the second reviewer as it merged
after, in `92fe668` (tangent.ref); not run again at that commit. The
enrichment data's date was not recorded.

| | Claude Haiku 5.5, the judge | with Claude Sonnet 5.5 reviewing |
|---|---|---|
| attacks caught, of 71 | 70 | 70 |
| our 36 | 36 | 36 |
| Stratus techniques from an address never seen, of 35 | 34 | 34 |
| the same from the member's usual place, of 35 (counted apart) | 35 | 28 |
| must-not-flag cases flagged, of 82 | 68 | 38 |
| a Stratus control from an address never seen, of 35 | 35 | 34 |
| a Stratus control from the usual place, of 35 | 23 | 2 |
| our 12 | 10 | 2 |
| ordinary records flagged, of 5,304 judged | 462 | 40 |

`score_v2.py`'s output for both is in
[compare/results/cloud/tangent](compare/results/cloud/tangent). The judge
left 4 of 6,832 records unjudged. The reviewer was given 1,577 alerts and
answered for 1,573 (three windows came back short, not looked into): 705
benign, 636 malicious, 232 unresolved, for $11.05 through Anthropic's API
(`harness/anthropic_proxy.py`), not Bedrock. The judge's cost was not
recorded.

The miss in both is `aws.persistence.iam-backdoor-role` from an address
never seen.

[compare/](compare/README.md) has Elastic's and Sigma's public rules over
the same records.

What is thin about it: one run of each, where two and `agree.py` were asked
for; the Stratus controls from an address never seen are flagged as often as
the attacks, and whether they should be is not settled; and the 36 are the
development set (below).

## The Google Workspace cases

**2026-11-25, three runs.** Six attacks and five look-alikes in Google
Workspace's login, token, drive and admin logs, added to the corpus with
ordinary Workspace traffic for every member (the stream had 884 Workspace
records before, and 20,679 after). The corpus is then 199 cases in 209
judged windows. Only the eleven windows holding the new cases were run:
690 records, arm `isolated`, tangent at `92fe668` (tangent.ref), Claude
Haiku 5.5 as the judge and Claude Sonnet 5.5 reviewing, both through
OpenRouter held to Anthropic as the host.

| | the judge, runs 1 to 3 | with the reviewer |
|---|---|---|
| attacks caught, of 6 | 6, 6, 6 | 6, 6, 6 |
| look-alikes flagged, of 5 | 5, 5, 5 | 2, 1, 2 |
| ordinary records flagged, of 580 judged | 38, 37, 44 | 18, 12, 13 |

`benign/workspace-helpdesk-reset-at-office` stands after review in all
three runs and `benign/workspace-delegation-audit-reader` in two. The
reviewer's verdict on both is unresolved, not malicious: it finds the usual
address, hours and device, and says the log cannot show whether the reset
or the new client and user were asked for. The attack whose app name tells
the reviewer what to answer is caught in all three.

The judge left 2 of 690 records unjudged in the first run and none in the
others. The reviewer answered for 134 of 136, 134 of 134 and 139 of 139
alerts. The three runs cost about $4.40.

What is thin about it: the other 188 cases were not run again on this
stream, so the table above them is still the 2026-11-15 run, on a stream
without the Workspace traffic. The ordinary records are those in the eleven
windows, not a sample of the stream. The cases were written the same day
they were measured, by the same hands; nothing in them or in the brief was
changed after the first run.

## Earlier layouts

Every number below came from the same corpus run through an earlier
harness, outside this repository, with other packs and another stream:

- **The packs.** The earlier runs used one cloud-infra pack (normalizer,
  enrichment and facts plugins, and a history plugin stamping `_hist`). Here
  each provider has its own pack, enrichment comes from the runtime's tables,
  norm drops fields that never decide a verdict, the profile's `people` sets
  the person, and core's baseline_builder and baseline_renderer give the
  judge `_baseline`. Each of these changes what the model reads.
- **The stream.** The agent's log was a source of another name; here it is
  `agent`, with renamed services. Every CloudTrail record gen.py writes now
  carries `recipientAccountId`, as the cases have since #48; the Stratus
  session tokens are redacted (the aws pack dropped them before the model
  either way). The case directories are named differently (`agents`,
  `benign`, `data-exfil`), and cases are placed in name order, so many land
  on other days than in earlier runs.

**v3 corpus, 201 cases.** Claude Haiku 5.5 on Bedrock,
logfmt, ten shards, four complete runs on 2026-10-31 and 11-01, two without
a history header and two with one (the `_hist` that `_baseline` replaced):

| | without the header | with it |
|---|---|---|
| our 45 attacks caught | 45/45, 45/45 | 45/45, 45/45 |
| ordinary records flagged, of 6,587 judged | 124 and 133 (1.9%, 2.0%) | 51 and 59 (0.8%, 0.9%) |
| cost per run | about $0.98 | about $1.02 |

Our 16 must-not-flag cases: 10 or 11 flagged in every run. Each run sent
921 requests. Run-to-run agreement per record: 98.2% without
the header, 99.3% with it. Two further runs were discarded because a shard
exited early.

**v2 corpus, 191 cases** (without the ten history cases), Haiku 5.5,
2026-10-30 and 10-31: our 40 attacks caught 40/40 in each of the four runs
re-scored for it.

**examples/cloud-infra's README** cites the shape before the actor-of-forty
judge (Haiku 4.5, every record judged in batches with each org's history):
38 to 39 of 40 attacks, 1 of 11 negatives, 13 of 16,199 ordinary records.

**Stratus Red Team**: every number measured on it before this layout is
withdrawn ([stratus/README.md](stratus/README.md#not-citable-yet)).

## What the numbers can say

Our cases are the development set: the judge's brief was revised while
running them, so recall on them is in-sample. The history pairs were written
to measure the history header. Nothing here estimates alerts a day for a real
company: only window hours are judged, they sit around business hours, and
acme has nine people.

With a result, record here: the date, the tangent commit, the enrichment
data's date, the arm (`isolated` or `shipped`), the model, and
`score_v2.py`'s and `agree.py`'s output for two runs.
