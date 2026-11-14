# Shai-Hulud

The npm worm of September and November 2025: a dependency's install script
runs a payload that hunts the machine for secrets, and with the developer's
own npm token republishes the packages they maintain with itself added, so
that everyone who installs those is next.

The recording is of a developer's Mac (a VM) where the person types
`npm install acme-retry` in their Terminal, and of nothing else they do.

## What happens in the recording

| step | what the sensor sees | from the write-ups |
|---|---|---|
| 1 | `npm install` runs the package's `preinstall`, `node setup.mjs` | the second wave's install script |
| 2 | Bun is not there, so Bun's own installer is fetched and run (`curl -fsSL https://bun.sh/install \| bash`), and `bun worker.js` is left running on its own while the install finishes | the second wave: Bun installed, the payload started detached |
| 3 | the payload reads `~/.npmrc`, runs `gh auth token`, and reads the AWS, gcloud and Azure credential files | both waves: npm, GitHub and cloud credentials |
| 4 | TruffleHog is downloaded from its GitHub release and run over the whole home directory | both waves; Red Canary's detection is TruffleHog with Bun as its parent |
| 5 | a connection to `api.github.com` | where the worm creates a repository and uploads what it found |
| 6 | each of the developer's packages is fetched, unpacked with `tar`, given the install script, and `npm publish`ed | both waves: how it spreads |

`twin.sh` is the same kinds of acts by the person on their own work: Bun
installed by its installer, their own package scanned with TruffleHog, a new
version published.

## What is real and what is stood in

Real: every program, every file read and written, every process's parent, the
downloads of Bun and TruffleHog from their own hosts, the connection to
GitHub's API, `npm publish` itself.

Stood in:

- **The registry.** `registry.npmjs.org` in the VM is
  [`standin/registry.py`](../../standin/registry.py) on the host, so the
  connections carry the registry's name and a private address. The infected
  package comes from it and the republished ones go to it and nowhere else.
- **What is sent.** Nothing the payload reads is kept or sent. Where the worm
  uploads its findings, this makes one request to the same host that carries
  nothing. A sensor sees a connection, not what is in it.
- **The credentials.** Random bytes in the right files and shapes, made when
  the VM is provisioned.
- **The names.** The package (`acme-retry`), the files (`setup.mjs`,
  `worker.js`) and the developer's packages are made up; the worm's own file
  and repository names are not used, so that nothing is caught by a name.
- **TruffleHog's `--no-verification`.** The worm let TruffleHog test what it
  found against the services; here the planted credentials are not tried
  against anyone.

Not in the recording yet: the GitHub Actions runner the second wave registers
on the machine, and the wipe of the home directory it falls back to when it
finds no token.

The payload runs only on a recording VM (`/etc/tangent-eval-vm`, and a
`registry.npmjs.org` that resolves to a private address) and exits at once
anywhere else.

## Sources

See [`case.json`](case.json).
