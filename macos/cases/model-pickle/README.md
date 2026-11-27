# Malicious Hugging Face models (nullifAI)

The model repositories found on Hugging Face in February 2025 (ReversingLabs,
who named the technique nullifAI) and, of the same kind, a year earlier
(JFrog): a repository whose PyTorch weights file is a pickle, and a pickle
can say "call this function" to whoever loads it. Loading the file ran
Python that connected back to a hard-coded address and gave a shell to
whoever answered. ReversingLabs' two files were packed so that Hugging
Face's scanner did not flag them.

The recording is of a developer's Mac (a VM) where the person downloads a
model's weights file and loads it in Python to look at it, and of nothing
else they do.

## What happens in the recording

| step | what the sensor sees | from the write-ups |
|---|---|---|
| 1 | `curl` downloads `pytorch_model.bin` from the model hub's host, port 443, into a project directory | the file is in a repository on Hugging Face; no write-up says how a victim fetched it (see below) |
| 2 | the person's `python3` opens the file | JFrog: the code is put in the file with pickle's `__reduce__` and runs when the file is deserialized, as `torch.load()` does |
| 3 | that `python3` connects to `node.acme-relay.example` on port 4242 | JFrog: on anything but Windows, a thread connects a socket to a hard-coded address and port (4242 in the first repository) |
| 4 | that `python3` starts `/bin/sh`, with no arguments | JFrog: `pty.spawn("/bin/sh")` with the socket as its input and output. ReversingLabs: "a typical platform-aware reverse shell that connects to a hardcoded IP address" |
| 5 | the connection and the shell stay for 60 seconds with nothing sent, then both end and `python3` exits | JFrog's honeypot: the connection was held for a day and no command came |

`twin.sh` is the same kinds of acts by the person on their own work: a real,
small model's weights file (`hf-internal-testing/tiny-random-bert`, 520 kB)
downloaded from the real `huggingface.co` with `curl`, the library that reads
it installed into a virtualenv from the real PyPI (`safetensors`, `numpy`),
and the file loaded in Python.

## What is real and what is stood in

Real: every program and its parent (`curl`, `python3`, `/bin/sh`), the file
written and opened, the pickle run by Python's own `pickle` module, the
connection from the loading Python itself, the port.

Stood in:

- **The model hub.** `hub.acme-models.example` in the VM is
  [`standin/registry.py`](../../standin/registry.py) on the host, which
  answers the one path with [`pytorch_model.bin`](pytorch_model.bin). The
  path has the shape of Hugging Face's download addresses
  (`<owner>/<model>/resolve/main/<file>`).
- **The attacker's address.** `node.acme-relay.example` is the same
  stand-in, answering plain HTTP on 4242; nothing is sent to it, so it says
  nothing. The real files carried bare IP addresses; here it is a name,
  because the stand-in is reached by name.
- **The shell.** In the real payload the shell's input and output are the
  connection. Here the shell is given a pipe nothing is written to and the
  connection is only held: no command is taken and none is run. The shell
  is started with `subprocess`, not on a pseudo-terminal as `pty.spawn`
  does.
- **The loader.** The person loads the file with `pickle.load`, from the
  standard library, where a real victim would call `torch.load` (or a
  library that calls it). `torch.load` unpickles with the same `pickle`
  machinery, so the same code runs in the same process; PyTorch is about
  200 MB and is not installed for this. (Since PyTorch 2.6 `torch.load`
  refuses such calls unless asked with `weights_only=False`; the incidents
  are older.)
- **The file.** A plain pickle of a small dictionary shaped like weights,
  with the call first. It was made by running `python3 make_model.py`, which
  reads [`on_load.py`](on_load.py) and writes the file; making it runs none
  of `on_load.py` (pickle only writes down "call `exec` with this text"), and
  the file has not been loaded outside a recording. JFrog's files were
  PyTorch's zip archives with the pickle inside. ReversingLabs' were packed
  with 7z instead, and the pickle was broken after the call so that it ran
  and then the load failed; neither is done here (rule 5).
- **The names.** The hub, the model (`acme-lab/tiny-sentiment`) and the
  address are made up. The port is the one in JFrog's first repository.

Filled with the plainest thing, where the write-ups give no detail: how the
person gets the file (`curl`; the write-ups examine the repositories, not a
victim's machine), how long the connection lasts (60 seconds), and the port
for ReversingLabs' files (their post gives the address only).

Not in the recording:

- **What the shell was used for.** No write-up reports a command sent to any
  machine, so none is invented.
- **The 7z packing and the broken pickle**, which are there to get past the
  scanner on the hub, not anything a Mac's sensor sees differently.
- **The Windows branch**, which starts `powershell.exe` and relays between
  it and the socket.
- **`torch.load` itself**, as above.

The payload runs only on a recording VM (`/etc/tangent-eval-vm`, and a
`node.acme-relay.example` that resolves to a private address) and does
nothing anywhere else.

## Needs in the VM

Nothing that `vm/provision.sh` does not give. The attack uses only the
standard library. The twin's `pip install` trusts the real PyPI through
pip's machine-wide config, which `record.sh` writes, and its `python3` must
be able to make a virtualenv with pip in it. The last typed line of the
attack returns only after the 60 seconds, because the thread keeps the
person's Python alive, as the real payload's does. The recording leaves
`~/code/acme-sentiment` behind, and the twin `~/code/acme-embed`.

## Sources

See [`case.json`](case.json).
