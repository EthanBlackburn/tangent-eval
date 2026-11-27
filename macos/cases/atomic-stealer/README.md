# Atomic Stealer

Not recorded yet: the payload is Ethan's to write. Everything around it is
here, and this page is finished once the payload is.

## What is here

- `case.json`: one attacker's host, `get.acme-update.example`, which in the
  VM is the stand-in. It answers `/update` with `update.sh` from this
  directory and takes anything sent to it, keeping no content. Add
  `http_ports` or more `serve` paths (a second stage) as the payload needs,
  and the write-ups it follows under `sources`.
- `attack.sh`: the one line the person pastes.
- `twin.sh`: an installer script run from `curl`, `system_profiler`, and the
  person's documents zipped to the Desktop.

## What the payload has to keep to

`update.sh`, and anything it fetches or writes and runs, under the rules in
[`../README.md`](../README.md):

1. Its first act is to exit unless `/etc/tangent-eval-vm` exists and
   `get.acme-update.example` resolves to a private address. The same in
   every file it drops and runs.
2. Files are opened and read; the content is dropped. A staging folder or
   archive holds filler or random bytes of the same lengths. An upload to
   the host is filler.
3. No password prompt (decided 2026-11-13). `sudo` on the VM asks for none.
4. Made-up names for the files, folders and launch item; plain code.
5. A step of the write-ups that is left out goes under "Not in the
   recording" below.

What the VM holds for it to find is listed under "The VM" in
[`../README.md`](../README.md): placeholder Chrome and Firefox profiles, two
wallets, Documents and Desktop files, all random bytes.

## Recording it

```bash
bash -n cases/atomic-stealer/update.sh
TANGENT_ROOT=~/code/tangent ./record.sh atomic-stealer attack
TANGENT_ROOT=~/code/tangent ./record.sh atomic-stealer twin
python3 -I replay.py ../runs/macos/recordings/atomic-stealer/attack ../runs/macos/replay/atomic-stealer-attack-1
```

## What happens in the recording

To be written from the recording: step, what the sensor sees, where in the
write-ups it comes from.

## What is real and what is stood in

To be written with the payload.

## Not in the recording

To be written with the payload.
