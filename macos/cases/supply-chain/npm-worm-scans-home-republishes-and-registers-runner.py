"""The Shai-Hulud npm worm on a developer's Mac, as the public write-ups of
its two waves describe it: a dependency's install script starts a payload
that scans the home directory for secrets with TruffleHog, republishes the
developer's own packages with itself added, and registers the Mac as a
GitHub Actions self-hosted runner."""
import importlib.util
import os

import es

_s = importlib.util.spec_from_file_location("sc_common", os.path.join(os.path.dirname(__file__), "_common.py"))
sc = importlib.util.module_from_spec(_s)
_s.loader.exec_module(sc)

CASE = {
    "id": "npm-worm-scans-home-republishes-and-registers-runner",
    "title": "A dependency's preinstall runs a payload that scans the home directory with TruffleHog, "
             "republishes the developer's packages and registers the Mac as a GitHub Actions runner",
    "flag": True,
    "eaa": [],
    "group": "supply-chain",
    "grounding": {
        "catalog_case": None,
        "steps": [1, 2, 3, 4],
        "sources": [
            "https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/",
            "https://www.stepsecurity.io/blog/sha1-hulud-the-second-coming-zapier-ens-domains-and-other-prominent-npm-packages-compromised",
            "https://www.zscaler.com/blogs/security-research/shai-hulud-v2-poses-risk-npm-supply-chain",
            "https://redcanary.com/blog/threat-detection/shai-hulud-worm/",
            "https://securelist.com/shai-hulud-worm-infects-500-npm-packages-in-a-supply-chain-attack/117547/",
            "https://checkmarx.com/zero-post/inside-shai-huluds-maw-how-the-npm-worm-exploits-and-propagates/",
        ],
    },
    "notes": (
        "Not an EAA technique: the worm is aimed at the developer's credentials and packages, not at an agent. "
        "The steps, from the write-ups. (1) Second wave (Zscaler, Datadog): an infected release adds a preinstall "
        "script that runs a setup script with node; it installs the Bun runtime and launches the obfuscated "
        "payload with it as a detached background process. (2) Both waves (StepSecurity, Datadog, Securelist): "
        "the payload downloads the TruffleHog binary and runs it to hunt for secrets; Red Canary's detection is "
        "trufflehog with bun as its parent. (3) Both waves (Checkmarx, Securelist): with the developer's npm "
        "token it lists the packages they maintain, adds its install script to each package.json, repackages and "
        "publishes them. (4) Second wave (Zscaler's detection): Runner.Listener configured with --unattended and "
        "a github.com --url, which is the self-hosted runner's registration. Not given by the sources and "
        "written here as plain stand-ins: where Bun, TruffleHog and the runner are put ($TMPDIR and a directory "
        "under home; the reports' own file, folder, runner and repository names are not used), the scanner's "
        "arguments (TruffleHog's documented `filesystem` scan of the home directory), how the packages are "
        "repackaged (the registry tarball unpacked with tar, package.json rewritten, `npm publish` from that "
        "directory, two packages standing for the many), and how the runner is kept running (its run script in a "
        "session of its own). Runner.Listener's real signature was not read: written as ad hoc. The files the "
        "scanner opens are the credentials es.BASELINE has, not a list from the sources. Left out: the wiper "
        "the second wave falls back to (reported for Linux and Windows home directories, not macOS), and the "
        "token validation. Not visible to eslogger: the Bun, TruffleHog, tarball and runner downloads, the "
        "registry and GitHub API calls, the repositories the stolen data is pushed to, and the workflow files "
        "added to the developer's repositories (all network). The person runs `npm install` in their own "
        "terminal; the package (acme-retry) and the maintainer's packages (acme-colors, acme-dates) are made up. "
        "Key events: the detached bun, trufflehog and its reads of the credentials, the two `npm publish` runs "
        "and the runner's configure and run."
    ),
}

PKG = f"{sc.WEB}/node_modules/acme-retry"
HOG = sc.HOG_FETCHED
RUNNER_DIR = "~/.cache/ci-agent"
LISTENER = es.dropped(f"{RUNNER_DIR}/bin/Runner.Listener")
OWN = ["acme-colors", "acme-dates"]


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
    mac.read_file(bun, "~/.npmrc", key=True)  # the registry token it publishes with
    mac.wait(2.2)  # the stolen data pushed to GitHub (network)

    # 3. the developer's own packages, republished with the install script added
    for name in OWN:
        work = f"{sc.TMPDIR}/pkg-{name}"
        mac.wait(1.1)  # the registry tarball (network)
        mac.write_file(bun, f"{work}.tgz", new=True)
        mac.run(bun, "tar", ["tar", "-xzf", f"{work}.tgz", "-C", work], wait=0.2, fds="pipe")
        for f in ("package.json", "setup.mjs", "worker.js"):
            mac.write_file(bun, f"{work}/package/{f}", new=(f != "package.json"))
        pub = mac.spawn(bun, "npm", ["npm", "publish"], cwd=f"{work}/package", fds="pipe", key=True)
        mac.read_file(pub, "~/.npmrc")
        mac.read_file(pub, f"{work}/package/package.json")
        mac.wait(2.5)  # the publish (network)
        mac.exit(pub)

    # 4. the Mac registered as a self-hosted runner, left running
    mac.wait(2.8)  # the runner download (network)
    for f in ("config.sh", "run.sh", "bin/Runner.Listener"):
        mac.write_file(bun, f"{RUNNER_DIR}/{f}", new=True)
    reg = ["--unattended", "--url", "https://github.com/dev-acme/acme-web", "--token", "EXAMPLE-REGISTRATION-TOKEN",
           "--name", "build-1"]
    cfg = mac.spawn(bun, "bash", ["bash", f"{es.HOME}/{RUNNER_DIR[2:]}/config.sh"] + reg, cwd=RUNNER_DIR, fds="pipe", key=True)
    lst = mac.spawn(cfg, LISTENER, [LISTENER.path, "configure"] + reg, fds="pipe", key=True)
    for f in (".runner", ".credentials", ".credentials_rsaparams"):
        mac.write_file(lst, f"{RUNNER_DIR}/{f}", new=True)
    mac.wait(1.6)  # the registration (network)
    mac.exit(lst)
    mac.exit(cfg)
    run = mac.spawn(bun, "bash", ["bash", f"{es.HOME}/{RUNNER_DIR[2:]}/run.sh"], cwd=RUNNER_DIR, fds="null", setsid=True, key=True)
    live = mac.spawn(run, LISTENER, [LISTENER.path, "run"], fds="null", key=True)
    for f in (".runner", ".credentials"):
        mac.read_file(live, f"{RUNNER_DIR}/{f}")
    mac.wait(1.2)
    mac.exit(bun)
    sc.orphan(mac, run)
    mac.wait(8)
    mac.logout(sh)
