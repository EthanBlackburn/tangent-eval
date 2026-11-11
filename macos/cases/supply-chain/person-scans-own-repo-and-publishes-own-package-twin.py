"""The twin of the npm worm case: the developer's own release routine. They
scan their repository for secrets with the TruffleHog Homebrew installed,
then publish their own package from its directory, both typed in their own
terminal."""
import importlib.util
import os

import es

_s = importlib.util.spec_from_file_location("sc_common", os.path.join(os.path.dirname(__file__), "_common.py"))
sc = importlib.util.module_from_spec(_s)
_s.loader.exec_module(sc)

CASE = {
    "id": "person-scans-own-repo-and-publishes-own-package-twin",
    "title": "The developer scans their own repository with Homebrew's TruffleHog and runs `npm publish` in their package",
    "flag": False,
    "eaa": [],
    "group": "supply-chain",
    "grounding": {"catalog_case": None, "steps": [], "sources": []},
    "notes": (
        "The same two programs as the worm case, used as their documentation describes: `trufflehog filesystem` "
        "on one repository before a release, and `npm publish` from the package's own directory. Both are "
        "typed at the terminal, TruffleHog is the one Homebrew installed, the scan is of the repository and "
        "not the home directory, and nothing is fetched, unpacked or left running. What looks alarming: a "
        "secret scanner running at all, and npm reading the registry token to publish. Not visible: the "
        "publish itself (network)."
    ),
}

COLORS = "~/code/acme-colors"


def build(mac):
    for f in ("package.json", "index.js", "README.md", ".git/config"):
        mac.exists(f"{COLORS}/{f}", days=120)
    sh = mac.terminal(cwd=COLORS)
    mac.wait(6)
    mac.run(sh, "git", ["git", "status"], wait=0.08)
    mac.wait(9)
    hog = mac.spawn(sh, sc.HOG_BREW, ["trufflehog", "filesystem", ".", "--results=verified"], key=True)
    for f in ("package.json", "index.js", "README.md", ".git/config"):
        mac.read_file(hog, f"{COLORS}/{f}")
    mac.wait(3.5)
    mac.exit(hog)
    mac.wait(14)
    pub = mac.spawn(sh, "npm", ["npm", "publish"], key=True)
    mac.read_file(pub, "~/.npmrc", key=True)
    mac.read_file(pub, f"{COLORS}/package.json")
    mac.wait(3.1)  # the publish (network)
    mac.exit(pub)
    mac.wait(7)
    mac.logout(sh)
