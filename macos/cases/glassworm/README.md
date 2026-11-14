# GlassWorm

The worm in editor extensions, first reported in October 2025 on Open VSX and
the VS Code marketplace, which by its fourth wave (December 2025) had turned
to Macs: an extension with thousands of installs carries an encrypted
payload that, a quarter of an hour after the editor starts, takes the login
keychain, wallets, browser data and the developer's credentials, and stays.

The recording is of a developer's Mac (a VM) where the person installs an
icon theme for VS Code and opens their project, and of nothing else they do.

## What happens in the recording

| step | what the sensor sees | from the write-up |
|---|---|---|
| 1 | `code --install-extension` unpacks the extension into `~/.vscode/extensions`; `code ~/code/acme-web` starts the editor, whose extension process (`Code Helper (Plugin)`) loads it | an extension from the marketplace, run by the editor |
| 2 | twenty seconds on, that process connects to `api.mainnet-beta.solana.com` | the server's address is read from a note on the Solana ledger |
| 3 | it connects to the attacker's server | the next stage is fetched from there |
| 4 | it reads `~/Library/Keychains/login.keychain-db`, the wallet extensions' stores and `Cookies` in each Chrome, Brave and Edge profile, Firefox's `cookies.sqlite`, the Exodus and Electrum wallets, `~/.npmrc`, everything in `~/.ssh`, `~/.git-credentials` and the editor's own storage, and writes a file of the same name and length for each under `/tmp/qvkda/` | the list of what is taken; the staging folder in `/tmp` |
| 5 | it starts `osascript -e 'do shell script "security find-generic-password -s … -w"'` | AppleScript runs its shell commands; the `security` tool is asked for a named keychain item |
| 6 | it starts `osascript -e 'do shell script "zip -qr /tmp/qvkda.zip /tmp/qvkda"'` | what was collected is compressed |
| 7 | it POSTs about a megabyte to the attacker's server | the upload |
| 8 | it writes `~/Library/LaunchAgents/com.acme.fileicons.sync.plist` | a LaunchAgent, for the next login |
| 9 | it looks for `/Applications/Ledger Live.app` and `/Applications/Trezor Suite.app` | the hardware wallets' apps are replaced where found |

`twin.sh` is the same kinds of acts by the person on their own work: two real
extensions installed from the marketplace, the project opened, the project
zipped to the Desktop, and `osascript` for a notification.

## What is real and what is stood in

Real: the editor and its extension process, every file opened and written,
`osascript`, `sh`, `security` and `zip` and their parents, the connection to
the Solana endpoint.

Stood in:

- **The marketplace.** The person fetches the extension's file with `curl`
  from `ext.acme-market.example`, which in the VM is
  [`standin/registry.py`](../../standin/registry.py) on the host serving
  [`vsix/`](vsix) as a `.vsix`, and installs it with
  `code --install-extension`. In the incident the editor itself installed or
  updated the extension from Open VSX, so the `curl` line is not the
  incident's.
- **The attacker's server.** `sync.icons-cdn.example` in the VM is the same
  stand-in, which answers 200 with nothing. The real payload ran what the
  server sent; here the steps that follow are in the extension itself.
- **What is taken.** Every file in step 4 is read and its content dropped.
  What is written under `/tmp/qvkda/` is random bytes of the same lengths, so
  the archive is of the right size and holds nothing; the upload is filler
  as long as the archive.
- **The ledger.** One request to Solana's public endpoint asking whether it
  is up. No account is looked at.
- **The keychain item.** The write-up does not name the item asked for. Here
  it is `Acme Wallet`, which the VM's keychain does not have; the answer is
  not read.
- **The LaunchAgent.** The write-up does not say what the agent runs. This
  one runs `/usr/bin/true`, and is written but not loaded.
- **The wait.** Twenty seconds, where the real one waits fifteen minutes.
- **The files it reads.** The browser and wallet files on the VM are random
  bytes under the right names (`vm/provision.sh`); the login keychain is the
  VM's own, of a user made for the recording.
- **The names.** The extension, the hosts, the staging folder and the
  LaunchAgent's label are made up; the incident's own are not used, so that
  nothing is caught by a name.
- **The archiver.** The write-up says "compressed" and no more; `zip` is the
  plainest thing that does it.

Not in the recording: the spreading (the first waves used the npm, GitHub and
Open VSX tokens they took to infect more extensions), the replacement of the
hardware wallets' apps (none is installed, and the real servers were
answering with empty files when the write-up's authors tried), the remote
access the earlier waves installed (a proxy and a hidden desktop), the VPN
configurations, and the payload's encryption and invisible characters.

The payload runs only on a recording VM (`/etc/tangent-eval-vm`, and a
`sync.icons-cdn.example` that resolves to a private address) and exits at
once anywhere else.

## Needs in the VM

VS Code, which `vm/provision.sh` gives, with `~/code` trusted. The case's
sessions begin at the editor as well as at Terminal: `entry` in `case.json`. VS
Code may fetch its own update during a recording (`ShipIt`, `ditto`), in the
attack and the twin alike.

## Sources

See [`case.json`](case.json).
