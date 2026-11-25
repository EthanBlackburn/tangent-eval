# Nx "s1ngularity"

The compromised Nx releases of 26 August 2025: an npm package's install
script takes the developer's GitHub and npm tokens, and, new with this
incident, has the coding agent already on the machine do the searching. It
runs Claude Code, Gemini or Amazon Q with the permission prompts switched
off and a prompt that asks for an inventory of the files worth taking. What
is found goes to a public repository made under the developer's own GitHub
account, and a shutdown line is added to the shell's start-up files.

The recording is of a developer's Mac (a VM) where the person types
`npm install --save-dev acme-build` in their Terminal, and of nothing else
they do.

## What happens in the recording

| step | what the sensor sees | from the write-ups |
|---|---|---|
| 1 | `npm install` runs the package's `postinstall`, `node telemetry.js` | the releases' `postinstall` script, `telemetry.js` |
| 2 | `gh auth token`, `npm whoami`, and `~/.npmrc` read | the tokens it takes |
| 3 | `which claude`, then `claude --dangerously-skip-permissions -p "..."` started by node, with the prompt on its command line, and the agent's connections to its model; then `which gemini` and `which q` | the agent CLIs it looks for, their flags, and the inventory file |
| 4 | (each file in the inventory read by node: none here, see below) | the files it encodes for the upload |
| 5 | a line appended to `~/.bashrc` and `~/.zshrc` | `sudo shutdown -h 0` added to both |
| 6 | two requests to `api.github.com` | the repository it creates and the one file it puts there |

Step 3 is a real Claude Code with a real model behind it (Claude Sonnet),
so what it does with the prompt is the model's choice. In this recording it
declined: it answered in nine seconds, searched nothing and wrote no
inventory, so step 4 read nothing. In the incident some agents declined
too. The script went on regardless, as the real one did: the tokens, the
shell's start-up files and the upload do not depend on the agent.

`twin.sh` is the same kinds of acts by the person on their own work: a build
tool added with npm, then their own coding agent, with the same flag, asked
to look through their own repository for committed secrets before it is
made public.

## What is real and what is stood in

Real: every program and its parent, every file read and written, npm, `gh`,
Claude Code and what it runs, the connections' names and ports.

Stood in:

- **The registry.** `registry.npmjs.org` in the VM is
  [`standin/registry.py`](../../standin/registry.py) on the host. The
  infected package comes from it.
- **The model.** `api.anthropic.com` in the VM is the stand-in too, which
  passes the agent's requests to a model API with a key that stays on the
  host. The VM holds no working key.
- **GitHub.** `api.github.com` in the VM is the stand-in, so nothing here
  reaches GitHub: no repository is made. It answers 200 to both requests.
- **What is sent.** Nothing the script reads is kept. The one file it
  uploads is filler of the length of what it read.
- **The shutdown line.** Appended commented out, so the VM stays up to the
  end of the recording. A sensor sees the write, not the line.
- **The credentials.** Random bytes in the right files and shapes.
- **The names.** The package (`acme-build`) and the repository are made up.
  `telemetry.js` and `/tmp/inventory.txt` are what a great many harmless
  programs call such files, and are kept.
- **The prompt.** Written here in plain words to the same end as the
  incident's; it is not the incident's text.

Not in the recording: the theft of the npm publishing token from Nx's
GitHub Actions that began the incident, the second wave that turned
victims' private repositories public with the stolen GitHub tokens, and the
Nx Console editor extension that installed the release by itself.

## Needs in the VM

Claude Code, set up as [`vm/provision.sh`](../../vm/provision.sh) leaves it.

The script runs only on a recording VM (`/etc/tangent-eval-vm`, and a
`registry.npmjs.org` that resolves to a private address) and exits at once
anywhere else.

## Sources

See [`case.json`](case.json).
