"""The twin of the wiper case: the developer's own clean-up. They delete a
project they no longer work on and the SSH key they rotated out, with rm
typed in their own terminal."""
import importlib.util
import os

import es

_s = importlib.util.spec_from_file_location("sc_common", os.path.join(os.path.dirname(__file__), "_common.py"))
sc = importlib.util.module_from_spec(_s)
_s.loader.exec_module(sc)

CASE = {
    "id": "person-deletes-old-project-and-rotated-key-twin",
    "title": "The developer deletes an old project directory and a rotated-out SSH key with rm at their terminal",
    "flag": False,
    "eaa": [],
    "group": "supply-chain",
    "grounding": {"catalog_case": None, "steps": [], "sources": []},
    "notes": (
        "Plainly benign deletion by the rightful user: `rm -rf` of one project directory they name, then `rm` of "
        "an old key pair, both typed at their tty, nothing installed or scanned first and nothing else under "
        "home touched. What looks alarming: many files deleted at once, a `.env` and a private key among them. "
        "Key events: the two rm runs and the unlinks of the key pair and the project's `.env`."
    ),
}

OLD = "~/code/acme-legacy"
FILES = [".env", ".git/config", "package.json", "package-lock.json", "README.md", "src/index.js", "src/routes.js", "src/db.js"]
KEYS = ["~/.ssh/id_rsa_2023", "~/.ssh/id_rsa_2023.pub"]


def build(mac):
    for f in FILES:
        mac.exists(f"{OLD}/{f}", days=400)
    for f in KEYS:
        mac.exists(f, days=900)
    sh = mac.terminal()
    mac.wait(6)
    mac.run(sh, "ls", ["ls", "-la", mac._p(OLD)], wait=0.02)
    mac.wait(11)
    rm = mac.spawn(sh, "rm", ["rm", "-rf", mac._p(OLD)], key=True)
    for f in FILES:
        mac.unlink(rm, f"{OLD}/{f}", key=(f == ".env"))
    mac.wait(0.02)
    mac.exit(rm)
    mac.wait(19)
    mac.run(sh, "ls", ["ls", "-la", f"{es.HOME}/.ssh"], wait=0.02)
    mac.wait(9)
    rm = mac.spawn(sh, "rm", ["rm"] + [mac._p(k) for k in KEYS], key=True)
    for k in KEYS:
        mac.unlink(rm, k, key=True)
    mac.wait(0.01)
    mac.exit(rm)
    mac.wait(12)
    mac.logout(sh)
