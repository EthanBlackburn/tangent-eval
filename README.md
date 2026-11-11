# tangent-eval

What [tangent](https://github.com/EthanBlackburn/tangent)'s security packs are measured against, and how to measure them yourself. Everything here is synthetic except Datadog's Stratus Red Team recordings: the company in every case, acme, is fictional, and so are its people, accounts and repos.

## What tangent is evaluated against

Each row is a category of cases; its page lists every case and what the logs show in it. A case is a sequence of records in the shape of the real source (CloudTrail, the GitHub audit log, Okta, Google Workspace, CI job lines, runner egress, a product's audit log, an AI agent's log), with what the judge should say about it.

<!-- categories -->
| category | what it covers | should flag | must not |
|---|---|---|---|
| [Cloud infrastructure](cases/cloud/README.md) | AWS through CloudTrail: logging stopped, a root login without MFA, a bucket made public, a security group opened to the internet, a new IAM user given admin rights, a key first used from a new host, an outside account assuming a role | 7 | 0 |
| [Identity](cases/identity/README.md) | Okta, Google Workspace and a product's own logins: impossible travel, an admin signing in from a hosting provider abroad, MFA turned off or reset and re-enrolled elsewhere, a burst of failures then a success, a key or a promotion used minutes later, SSO bypassed | 10 | 0 |
| [GitHub](cases/github/README.md) | The org audit log: branch protection removed and main force-pushed, a contractor made owner with a deploy key, one token pushing to a dozen repos, a fork's pull request editing a workflow that runs with secrets, Shai-Hulud's repos and runner | 6 | 0 |
| [Supply chain](cases/supply-chain/README.md) | CI and dependencies: an Action's tags moved to a stealer, a postinstall that phones home, a typosquat, worms that publish credentials as repositories, a backdoored PyPI release, a trojaned axios | 8 | 0 |
| [Data exfiltration](cases/data-exfil/README.md) | One API key paging through every record, a service posting to a file-sharing site, a mailbox forwarding outside, a database snapshot shared with another account | 4 | 0 |
| [A vendor's breach](cases/vendor/README.md) | A connected AI app's stolen OAuth token used to pivot through SSO; a hosting vendor's leaked environment secrets reused | 2 | 0 |
| [SaaS and integrations](cases/saas/README.md) | An integration's stolen OAuth token reading everything; provider keys taken from a developer console and run up from everywhere | 2 | 0 |
| [AI agents](cases/agents/README.md) | An AI agent's own log: a plan reads a secret then posts where no plan named, retries with a different role each time, a tool result changes the task, a repository's settings redirect the model's calls and key, an MCP server copies every message out, an agent uses credentials it found | 6 | 0 |
| [Prompt injection](cases/prompt-injection/README.md) | Records written to talk to the reviewer: a key name, a user agent, a pull request title or a token name telling the judge what to answer | 4 | 0 |
| [Benign, must not flag](cases/benign/README.md) | What looks alarming and is not: Dependabot's weekly batch, the on-call's 3 a.m. login, a deploy's restart burst, a repo made public as planned, scanner probes, a rotation after a vendor's notice, the same sign-ins and reads as every day | 0 | 17 |
| all | | 49 | 17 |
<!-- /categories -->

Two more suites:

| suite | what it covers | should flag | must not |
|---|---|---|---|
| [Stratus Red Team](stratus/README.md) | 35 real AWS attack techniques Datadog recorded in its own test accounts, each spliced in as a member of acme whose credentials were stolen, from a hosting address and from the office; and for each, a control with every call made a harmless read | 70 | 70 |
| [macOS endpoint](macos/README.md) | 94 synthetic eslogger cases on a developer's Mac: 90 of AI-agent abuse, grounded in the [EAA catalog](https://github.com/0x4D31/endpoint-ai-agent-abuse), and the Shai-Hulud npm worm on a Mac, with its wiper, beside the developer's own release and clean-up; for tangent's macOS pack ([#85](https://github.com/EthanBlackburn/tangent/pull/85)) | 47 | 47 |

Every case lands on a day of its own inside thirteen months of acme's ordinary traffic ([the stream](#the-stream)), so the judge sees it the way it would in production: against the history of the people and systems involved.

## How good is it

No result has been measured on this layout yet. [RESULTS.md](RESULTS.md) says what was measured on earlier layouts of the same corpus (our 45 attacks caught in every run of four, about 2% of ordinary records flagged, 10 or 11 of 16 must-not-flag cases flagged), why none of it is this repository's number, and what to record when it is.

Two things limit what these numbers can say:

- **Our cases are in-sample.** The judge's brief (packs/core/judge.md) and the
  profile were revised while running them, and the history pairs were written
  to measure the judge's `_baseline`. A score on them says the pipeline still
  does what it was built to do, not how it does on attacks nobody here wrote.
- **Stratus numbers are not citable yet.** An audit on 2026-10-28 found that
  the splice could be told from acme's own traffic by things unrelated to the
  attack (every spliced case started at 13:00Z, its sign-ins carried the CLI's
  user agent, and more). In every run so far, the controls were flagged about
  as often as the attacks. All six tells are fixed and unmeasured.
  [stratus/README.md](stratus/README.md#not-citable-yet) lists them.

## Check it yourself

With Rust ([rustup](https://rustup.rs)) and Python 3.10 or later with PyYAML importable under `python3 -I`:

```bash
AWS_PROFILE=... make        # Claude Haiku 5.5 on Bedrock: about $1 a run
make JUDGE=local            # packs/core's judge at JUDGE_URL: free, well over an hour
make corpus                 # the corpus alone, no model
```

`make` fetches tangent at the commit in [tangent.ref](tangent.ref) into `tangent/` (or uses `TANGENT_ROOT=/path/to/your/checkout`), builds it and its plugins, generates the corpus, replays it and prints the score. The sections below are the same steps one at a time. A judged run calls a model and costs what the table says; everything else is free.

## Layout

```
cases/           our 66 cases, by category, with a README per category (index.py writes them from gen.py)
stratus/         Datadog's 35 recorded techniques and splice.py, which makes the 140 Stratus cases
profile/         acme as the judge knows it
harness/         replay, shard, score
datasets/        third-party datasets for writing cases: pins in the tree, copies from a release (fetch.py)
gen.py           writes cases/; stream.py places every case inside the ordinary traffic
RESULTS.md       every number, with what it was measured on
```

## The stream

`stream.py v3` puts every case on a day of its own (Tuesday to Saturday;
two cases that share an actor at least ten days apart) inside thirteen months
of acme's ordinary traffic from every source: sign-ins, the product's API
traffic, pushes and pull requests, CI builds, each member's own AWS work, the
agent's health checks, poller and plans. 207,886 records:

| source | records |
|---|---|
| `agent` | 136,946 |
| `cloudtrail` | 21,271 |
| `app` | 20,072 |
| `okta` | 13,412 |
| `github_audit` | 9,240 |
| `gha_ci` | 3,302 |
| `runner_egress` | 2,750 |
| `google_workspace` | 893 |

`truth-v3.json` says, per case, whether it should flag, its actor and org as
the packs normalize them, the times of its events and the stream lines that
are its records. `past.py` moves both 104 weeks back, because the sqlite sink
takes no time from the future. `windows.py` makes the judged windows: an hour
either side of every case event, merged, 220 windows and 453 hours. Records
outside a window are ingested as history and never judged.

## One command

With Rust ([rustup](https://rustup.rs)) and Python
3.10 or later with PyYAML importable under `python3 -I`:

```bash
AWS_PROFILE=... make     # Claude Haiku 5.5 on Bedrock: about $1 a run
make JUDGE=local         # packs/core's judge at JUDGE_URL: free, well over an hour
make corpus              # the corpus alone, no model
```

It first makes whatever is missing or older than what it is made from: the
corpus, tangent, the packs' plugins, and the enrichment data if there is none
(`make -C tangent/examples/cloud-infra setup` refreshes it). Then it replays the
corpus in ten shards (`SHARDS`) in a run directory of its own,
`runs/<judge>-<time>` (`RUN=runs/NAME` names another), and prints the score, which `score.txt` there keeps. `TANGENT`
uses a tangent you built instead of building one. One run at a time in a
checkout: a run reads the corpus and plugins until it ends, so another
refuses to start while it does. The sections below are the same steps one at
a time.

## Generate (no model)

Python 3.10 or later, with PyYAML importable under `python3 -I` (installed
for the interpreter or in a venv, not with `pip --user`):

```bash
python3 -I gen.py                      # rewrites cases; git status stays clean
python3 -I stream.py v3                # runs/stream/{stream,truth}-v3.*
python3 -I harness/past.py v3          # runs/stream/{stream,truth}-past-v3.*
python3 -I harness/windows.py runs/stream/truth-past-v3.json runs/windows-v3.json
python3 -I harness/isolation.py --v3   # cases with another case among an actor's latest 40 records
```

Everything generated goes under `runs/`, which git ignores. `stream.py`
with no argument writes the older 191-case stream, without the history cases.

## Build tangent and the plugins

```bash
cd tangent && cargo build --release -p tangent-cli      # the checkout make fetched, or your own
export TANGENT=$PWD/target/release/tangent
make -C examples/cloud-infra compile TANGENT=$TANGENT
cd ..
```

`make compile` runs `setup.sh` first: the WASM toolchain, and the enrichment
data (GeoLite2, the cloud providers' ranges, the Tor exit list) into
examples/enrich/data. That data is fetched when you run it and changes over
time, so note the date with a result. A compiled plugin (`.cwasm`) only loads
in the tangent build that compiled it: compile again after every rebuild.
`replay.py` refuses to start without `TANGENT`.

## Make a run directory

```bash
python3 -I harness/maincfg.py isolated runs/h1             # Haiku 5.5 on Bedrock
python3 -I harness/maincfg.py isolated runs/l1 --judge local
```

`maincfg.py` merges tangent's examples/cloud-infra `ingest.yaml` and `judge.yaml`
with their includes and changes only what a replay needs: one tcp source for
the stream, paths into the run directory, the eval profile
([profile/profile.yaml](profile/profile.yaml)), and the judge's model.

- `isolated` folds the ordinary stream plus only the current window's cases
  into the state the judge's `_baseline` is read from, so no case sees
  another's history. Use it for numbers about the corpus.
- `shipped` is the example exactly as it runs, with every record, every
  case's included, folded into one state; an earlier case's calls and
  addresses are then "seen" for a later one. Report it beside `isolated`.
- `--judge bedrock` (the default) is Claude Haiku 5.5: thinking off,
  `max_tokens` 400, no temperature or top_p (5.5 refuses them), 16 requests
  at once. `BEDROCK_MODEL` and `BEDROCK_REGION` (us-west-2) override it, and
  `AWS_PROFILE` names the profile it signs in with.
- `--judge local` is packs/core's judge as it ships: any OpenAI-compatible
  server at `JUDGE_URL` (http://localhost:8080/v1), `JUDGE_MODEL`
  (glm-4.7-flash), one request at a time.

Use a new run directory for every run: the shards' sinks append.

## Check it for free

In a run directory of its own, so no judged run starts with its files:

```bash
python3 -I harness/maincfg.py isolated runs/sim
TRUTH=runs/stream/truth-past-v3.json SIMULATE=1 \
  python3 -I harness/replay.py runs/sim runs/stream/stream-past-v3.ndjson runs/windows-v3.json
```

`SIMULATE=1` runs ingest for real and forms the judge's requests without
sending them: `sim.json` in the run directory has the groups, requests,
records, context records and bytes a judged run will send. Each window's line
on stderr says how many rows of finished cases left `logs.sqlite`; that they
are found at all says truth's keys match what the packs wrote. Look in
`ingest.log` for records no pack took, and on stderr for "records not
stored". The judged runs below get directories of their own (`h1`,
`h2`).

`JUDGE=judge-sim.yaml` with `TRUTH` and without `SIMULATE`, again in a
directory of its own, stamps every judged record with its `_baseline` and
writes it to `headers.ndjson`, still with no model; `harness/headers.py TRUTH
WORK` prints what the judge would read for each attack and its twin.

## Run it

Bedrock, ten shards:

```bash
export TANGENT=... TRUTH=runs/stream/truth-past-v3.json
export AWS_PROFILE=...                 # one that can call Bedrock in BEDROCK_REGION; maincfg.py writes it into judge.yaml
export AWS_WAIT_PROFILE=$AWS_PROFILE   # on errors, wait for this profile's credentials, put the records back, go on
python3 -I harness/maincfg.py isolated runs/h1
python3 -I harness/shard.py runs/h1 runs/stream/stream-past-v3.ndjson runs/windows-v3.json 10 \
  > runs/h1/shard.out 2>&1
```

Shard k replays the windows before its own as history, so the result is the
same as one replay, about N times sooner. Each shard's progress is in
`s<k>/run.log`. A run stops on "judge stalled" (nothing judged for `STALL`
seconds, 900), or after three credential recoveries in ten minutes; a single
`replay.py` resumes with `FROM_WINDOW=k`. When judge.yaml names a profile,
replay.py drops `AWS_BEARER_TOKEN_BEDROCK` from the judge's environment,
because a token there is used instead of the profile; to sign in with a
Bedrock bearer token, leave `AWS_PROFILE` unset when you run maincfg.py, and
the token stays.

On the earlier plugin set a run took about 11 minutes at ten shards and cost
about $1 on Haiku 5.5 (921 requests, about 7 million tokens in). This layout
has not been run yet. Haiku 5.5 takes no sampling settings and two runs agree
on 98 to 99% of records, so make two runs of each arm and compare them with
`agree.py`.

A local model: serve it with the `llama-server` line in
[packs/core/README.md](https://github.com/EthanBlackburn/tangent/blob/main/packs/core/README.md), one model server at a time,
make the run directory with `--judge local`, and run `shard.py` the same way.
The server is the bottleneck: at about five seconds a request on one
machine, a run takes well over an hour. It has not been measured on this
shape.

## Score it

```bash
python3 -I harness/score_v2.py runs/stream/truth-past-v3.json runs/h1
python3 -I harness/agree.py runs/stream/truth-past-v3.json runs/h1 runs/h2
```

What `score_v2.py` reports:

- **recall**: an attack is caught when the judge flags any record of the
  case's actor (or of its org, for a case with no actor; agent records have
  only an org) in the two hours ending at the case's last event. The stricter
  count needs the flag on one of the case's own records.
- **negatives flagged**: the same rule over the 87 must-not-flag cases.
- **ordinary**: judged records that are no case's, flagged over judged. They
  are acme's synthetic traffic inside the windows, which sit around business
  hours, so this is a flag rate, not alerts a day for a real company.
- **not judged**: records whose verdict is an error (a failed request, or a
  record the model's answer skipped). Counted, not retried.
- **by suite**, each **attack against its twin**, **Stratus by what decides
  it** (stratus/grounding.yaml: one event, the actor's habits, or volume), and
  the **requests**, records read (context included) and megabytes the model
  read (measured as JSON; logfmt sends fewer).

`agree.py` matches two runs record by record (a record's content without its
verdict) and says how often the verdict agrees and which attacks only one run
caught.

`score_union.py` scores the judge and an ingest-side tripwire as one: recall
for each and for either, flags on ordinary records, and incidents (one org
and actor's flags with no gap over an hour) per 24 judged hours. It needs a
tripwire, and none is in this repository yet: it scores a run directory made
with `maincfg.py ... --tripwire NAME=PATH` (a deterministic ingest plugin
that passes on only the records it trips on, each with a `tripwire` key) and
compiled with `$TANGENT plugin compile --config WORK/ingest.yaml`, which
`make compile` does not do. After `shard.py`, join the shards' output first:

```bash
cat runs/t1/s*/tripwire.ndjson > runs/t1/tripwire.ndjson
python3 -I harness/score_union.py runs/stream/truth-past-v3.json runs/t1 runs/windows-v3.json [TRIPWIRE.ndjson]
```

[RESULTS.md](RESULTS.md) says which results exist.
