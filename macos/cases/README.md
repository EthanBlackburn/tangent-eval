# Cases

One directory per incident a reader has heard of. A case is the attack as a
sensor on the Mac would see it, run for real in a VM and recorded
([`../record.sh`](../record.sh)), and a twin: the same kinds of acts by the
person, on their own work. [`shai-hulud`](shai-hulud) is the model to copy.

```
cases/<id>/
  case.json     id, title, registry, pypi, hosts, http_ports, serve, repos, settle, sources
  attack.sh     what the person types in Terminal that sets it off
  twin.sh       what the person types for the twin
  README.md     the incident, what happens in the recording, what is real and what is stood in, what is not recorded
  ...           the payload: whatever the attack delivers and runs
```

## case.json

| key | |
|---|---|
| `id` | the directory's name |
| `title` | one sentence: the incident's name, then what it does on the Mac |
| `registry` | directories here that hold npm packages (`<dir>/<name>/package.json`): the stand-in serves them as `registry.npmjs.org` and takes what is published. Every other package comes from the real registry |
| `pypi` | directories here that hold PyPI projects (`<dir>/<name>/pyproject.toml` beside the files to install): the stand-in serves each as a wheel, as `pypi.org` and `files.pythonhosted.org`. Every other project comes from the real PyPI |
| `hosts` | names the attack talks to that are the attacker's: in the VM they resolve to the stand-in, which answers 200 to anything over TLS on 443 and keeps no content |
| `http_ports` | ports where the stand-in also answers plain HTTP for those names |
| `serve` | what the stand-in answers a host's path with, `{"host/path": "file here"}`: the payload the attack downloads. A directory is served as a zip of its files (an editor extension's `.vsix`). Any other request to the case's hosts gets an empty 200 |
| `repos` | git repositories a host holds, `{"host/path.git": "directory here"}`: the stand-in serves the directory's files as a repository of one commit, so that `git clone https://host/path.git` works in the VM |
| `entry` | where the case's sessions begin, by which they are told from the VM's own: the app the lines are typed into (default `Terminal`). A case that runs inside an app its lines open names both, as the pack names them: `["com.microsoft.VSCode", "Code", "Terminal"]` (the editor's session goes by either of the first two) |
| `settle` | seconds to keep recording after the last typed line returns |
| `sources` | the public write-ups the steps come from |

## attack.sh and twin.sh

Not scripts: lines typed into the VM's Terminal by real keystrokes, one at a
time, the next once the shell is idle. `#` lines and blank lines are skipped.
Each line is one complete command a person would type. No shebang. A line
that opens an app (`code ~/code/acme-web`) gives that app the keyboard, and
what is typed after it does not reach Terminal: it goes last.

A line that begins `>> ` is an answer to something the line before left on
screen and waiting: a password dialog, a prompt. It is typed five seconds
later to whatever has the keyboard, with Return, without waiting for the
shell. So the line before a `>> ` line is not waited for either. The VM's
login password is `admin`.

## The VM

macOS 26, user `admin` (/Users/admin), Homebrew, `node` and `npm`, `gh`,
`trufflehog`, `git`, `python3`, `curl`, and VS Code (`code` on the PATH). In the home: an npm token in
`~/.npmrc`, AWS keys in `~/.aws/`, an SSH key, a GitHub token in
`~/.config/gh/hosts.yml` (all random bytes in the right shapes), and the
projects `~/code/acme-web` (an app with real dependencies), `~/code/acme-colors`
and `~/code/acme-dates` (packages the person publishes). The person's own
files are there too, as random bytes under the right names (the browsers and
wallets themselves are not installed):

- Chrome, in `~/Library/Application Support/Google/Chrome`: `Local State`, and
  in `Default` the files `Login Data`, `Cookies`, `Web Data`, `History` and
  one wallet extension's store,
  `Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/000003.log`
- Firefox, in `~/Library/Application Support/Firefox/Profiles/<8 characters>.default-release`:
  `logins.json`, `key4.db`, `cookies.sqlite`, `formhistory.sqlite`
- wallets: `~/Library/Application Support/Exodus/exodus.wallet`
  (`seed.seco`, `info.seco`, `passphrase.json`) and
  `~/.electrum/wallets/default_wallet`
- `~/Documents`: `notes.txt`, `acme-q3-plan.pdf`, `invoice-0412.pdf`,
  `budget.docx`
- `~/Desktop`: `todo.txt`, `wifi.txt`

VS Code has been opened before and trusts `~/code`, so a folder under it
opens with no question, and its settings have `task.allowAutomaticTasks`
on, so a task a folder sets to run on opening does run. Terminal reads Documents and Desktop with no privacy prompt, and `sudo` asks
for no password. The stand-in's
certificate authority is trusted by the system and by npm; `curl` accepts it.
Bun's and node's own `fetch` do not read the keychain: a payload passes
`tls: { rejectUnauthorized: false }` (Bun) or the like, which no sensor sees.
The VM reaches the real internet: a legitimate download (Bun, a GitHub
release) is fetched from where the real attack fetched it.

What a case needs that is not there (an app installed, a browser profile, a
file) goes in its README under "Needs in the VM"; `vm/provision.sh` is not a
case's to edit.

## Rules

1. **What a sensor sees is done for real.** The same programs started by the
   same parents, the same files opened and written, connections to the same
   kind of host on the same port. Follow the write-ups step by step, in their
   order.
2. **Nothing is taken.** What the payload reads is not kept and not sent. A
   request to the case's `hosts` may carry filler of about the right size,
   never anything from the machine. A sensor sees a connection, not what is
   in it.
3. **It runs only in a recording VM.** The first thing every script and
   binary of the payload does: exit unless `/etc/tangent-eval-vm` exists and
   one of the case's `hosts` (or `registry.npmjs.org`) resolves to a private
   address. See `shai-hulud/infected/acme-retry/worker.js`.
4. **Made-up names.** Packages, files, hosts (under `.example`, or
   `example.com`, `.net`, `.org`), launch-item labels: none is the incident's
   own, so that nothing is caught by a name. The incident is named in
   `case.json` and the README only.
5. **Plain code.** No obfuscation, no packing, no technique for getting past a
   detector or an analyst. Short and readable.
6. **Said, not invented.** A step the write-ups give without detail is filled
   with the plainest thing that does it, and the README says so. A step that
   cannot be done here (it needs a real account, a real victim, a kernel
   exploit) is left out and listed under "Not in the recording".
7. **The twin is ordinary.** The rightful person doing the same kinds of
   things for their own reasons, with the real tools. It is not an attack
   made to look innocent.
8. **Nothing is run on the host.** A case is written and syntax-checked
   (`node --check`, `bash -n`); it runs only through `record.sh`.
