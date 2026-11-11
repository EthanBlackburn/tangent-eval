"""The Shai-Hulud npm worm's second wave when it comes away with nothing: the
payload scans the home directory, cannot get a GitHub or an npm token it can
use, and deletes the user's files under home instead."""
import importlib.util
import os

import es

_s = importlib.util.spec_from_file_location("sc_common", os.path.join(os.path.dirname(__file__), "_common.py"))
sc = importlib.util.module_from_spec(_s)
_s.loader.exec_module(sc)

CASE = {
    "id": "npm-worm-finds-no-token-and-wipes-home",
    "title": "A dependency's preinstall runs a payload that scans the home directory with TruffleHog, "
             "gets no usable token and deletes the user's files under home",
    "flag": True,
    "eaa": [],
    "group": "supply-chain",
    "grounding": {
        "catalog_case": None,
        "steps": [1, 2, 3],
        "sources": [
            "https://securelist.com/shai-hulud-2-0/118214/",
            "https://thehackernews.com/2025/11/second-sha1-hulud-wave-affects-25000.html",
            "https://www.reflectiz.com/blog/shai-hulud-2-0/",
            "https://redcanary.com/blog/threat-detection/shai-hulud-worm/",
            "https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/",
            "https://www.zscaler.com/blogs/security-research/shai-hulud-v2-poses-risk-npm-supply-chain",
        ],
    },
    "notes": (
        "Not an EAA technique. The steps, from the write-ups. (1) and (2) are the worm case's "
        "(npm-worm-scans-home-republishes-and-registers-runner): the preinstall that installs Bun and leaves the "
        "payload running detached, and the TruffleHog scan. (3) Securelist: when the malware gets no valid npm "
        "token and no valid GitHub token, so cannot exfiltrate, it runs a destructive payload that wipes the "
        "user's files, mainly in the home directory. The Hacker News: every writable file the current user owns "
        "under their home folder. Reflectiz names Linux, macOS and Windows; Red Canary reports attempts on "
        "Windows profiles and Linux home directories, so on a Mac this is the capability as described, not an "
        "observed incident. Not given by the sources read for this case and written plainly: how the files are "
        "deleted (the payload's own unlinks, with no command line and no overwrite pass), their order (path "
        "order), and how long it takes. The files are the ones es.BASELINE gives dev's home, standing for the "
        "whole of it; the login keychain is among them. Not visible to eslogger: the Bun and TruffleHog "
        "downloads, the token checks that fail, and the search of GitHub for an earlier victim's token (all "
        "network). The person runs `npm install` in their own terminal; the package (acme-retry) is made up. "
        "Key events: the detached bun, trufflehog and its reads of the credentials, and the unlinks of what is "
        "outside the repositories (credentials, shell and git configuration, agents' settings and history)."
    ),
}

PKG = f"{sc.WEB}/node_modules/acme-retry"
HOG = sc.HOG_FETCHED


def build(mac):
    sh = mac.terminal(cwd=sc.WEB)
    mac.wait(5)
    # 1. the install, and the preinstall that fetches Bun and leaves the payload running
    npm = mac.spawn(sh, "npm", ["npm", "install", "acme-retry"])
    for f in ("~/.npmrc", f"{sc.WEB}/package.json", f"{sc.WEB}/package-lock.json"):
        mac.read_file(npm, f)
    mac.wait(3)
    for f in ("package.json", "index.js", "setup.mjs", "worker.js"):
        mac.write_file(npm, f"{PKG}/{f}", new=True)
    s = es.npm_lifecycle(mac, npm, PKG, "node setup.mjs", event="preinstall", version="2.4.1")
    mac.exec(s, "node", ["node", "setup.mjs"])
    mac.read_file(s, f"{PKG}/setup.mjs")
    mac.wait(2.4)  # the Bun download (network)
    mac.write_file(s, sc.BUN.path, new=True)
    bun = mac.spawn(s, sc.BUN, [sc.BUN.path, "worker.js"], fds="null", setsid=True, key=True)
    mac.wait(0.01)
    mac.exit(s)
    sc.orphan(mac, bun)
    mac.read_file(bun, f"{PKG}/worker.js")
    mac.write_file(npm, f"{sc.WEB}/node_modules/.package-lock.json", new=True)
    mac.write_file(npm, f"{sc.WEB}/package.json")
    mac.write_file(npm, f"{sc.WEB}/package-lock.json")
    mac.exit(npm)

    # 2. the secret scan of the home directory
    mac.wait(1.9)  # the TruffleHog download (network)
    mac.write_file(bun, HOG.path, new=True)
    hog = mac.spawn(bun, HOG, [HOG.path, "filesystem", es.HOME, "--json"], fds="pipe", key=True)
    mac.wait(0.6)
    for f in sc.HOME_SECRETS:
        mac.read_file(hog, f, key=True)
        mac.wait(0.03)
    for f in sc.HOME_OTHER + [f"{sc.WEB}/package.json", f"{sc.WEB}/src/index.ts", "~/code/acme-api/src/main.rs"]:
        mac.read_file(hog, f)
    mac.wait(4)
    mac.exit(hog)
    mac.read_file(bun, "~/.npmrc")
    mac.wait(3.5)  # the npm and GitHub token checks, which fail (network)

    # 3. no token it can use: the user's files under home, deleted
    for path in sorted(p for p in mac.files if p.startswith(es.HOME + "/")):
        mac.unlink(bun, path, key=not path.startswith(es.HOME + "/code/"))
        mac.wait(0.002)
    mac.wait(0.4)
    mac.exit(bun)
    mac.wait(8)
    mac.logout(sh)
