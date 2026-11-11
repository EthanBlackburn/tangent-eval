"""Shared names for the supply-chain cases (gen.py skips files that start
with `_`). Load it from a case with:

    import importlib.util, os
    _s = importlib.util.spec_from_file_location("sc_common", os.path.join(os.path.dirname(__file__), "_common.py"))
    sc = importlib.util.module_from_spec(_s); _s.loader.exec_module(sc)

Programs not in es.PROGRAMS. TruffleHog is a Go binary: its releases'
signature was not read with codesign, so both copies are written as
linker-signed ad hoc, as every arm64 binary at least is."""
import es

P = es.Program

TMPDIR = "/var/folders/7x/k2m9q4z51b3c0000gn/T"
WEB = "~/code/acme-web"

# an official Bun build (Oven's signature), unpacked where a script put it
BUN_DIR = f"{TMPDIR}/bun-darwin-aarch64"
BUN = P("bun (fetched)", f"{BUN_DIR}/bun", "bun", "7FRXF46ZSN", es.DEVID_TOOL, size=63072928)
# TruffleHog as a script fetched it, and as Homebrew installs it
HOG_FETCHED = es.dropped(f"{TMPDIR}/th-darwin-arm64/trufflehog", "trufflehog")
HOG_BREW = P("trufflehog", "/opt/homebrew/Cellar/trufflehog/3.90.8/bin/trufflehog", es._adhoc("trufflehog"), cs=es.ADHOC,
             dyld="/opt/homebrew/bin/trufflehog", size=148203520)

# the credentials a secret scanner pointed at a home directory opens,
HOME_SECRETS = [
    "~/.npmrc",
    "~/.aws/credentials",
    "~/.ssh/id_ed25519",
    "~/.config/gh/hosts.yml",
    "~/.claude.json",
    "~/.codex/auth.json",
]
# and the ordinary dotfiles it opens beside them
HOME_OTHER = ["~/.aws/config", "~/.ssh/config", "~/.gitconfig", "~/.zshrc"]


def orphan(mac, proc):
    """`proc`'s parent has exited: launchd adopts it (`ppid` 1), and
    `original_ppid` keeps the parent it was born to."""
    proc.ppid = 1
    proc.parent_token = mac._token(mac.launchd)
