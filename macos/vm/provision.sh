#!/bin/bash
# provision.sh HOST_IP CA_PEM CASES_DIR SSH_PUBKEY: run once inside a fresh VM, as its
# user, to make it a developer's Mac that a recording can be made on. The
# registry stand-in (standin/registry.py) must be answering on HOST_IP.
#
# It marks the VM as a recording VM (the cases' payloads run nowhere else),
# points registry.npmjs.org at the host and trusts the stand-in's authority,
# installs what a JavaScript developer has (VS Code among it), and plants credentials: made here
# from random bytes, in the right files and the right shapes, good for
# nothing.
set -euo pipefail
host_ip=${1:?usage: provision.sh HOST_IP CA_PEM CASES_DIR SSH_PUBKEY}
ca=${2:?}
cases=${3:?}
pubkey=${4:?}

# record.sh's way in, kept out of the home directory a case may read
sudo mkdir -p /etc/ssh/keys
sudo cp "$pubkey" /etc/ssh/keys/"$(id -un)"
echo "AuthorizedKeysFile /etc/ssh/keys/%u" | sudo tee /etc/ssh/sshd_config.d/050-tangent-eval.conf >/dev/null

sudo touch /etc/tangent-eval-vm
grep -q registry.npmjs.org /etc/hosts || echo "$host_ip registry.npmjs.org" | sudo tee -a /etc/hosts >/dev/null
sudo cp "$ca" /etc/tangent-eval-ca.pem
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain /etc/tangent-eval-ca.pem

export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ENV_HINTS=1
eval "$(/opt/homebrew/bin/brew shellenv)"
brew install node gh trufflehog
# the editor, for the cases that arrive as an extension or a workspace task.
# Opened by a command, not a double click, so the downloaded-app question is
# taken off here and not answered in a recording.
brew install --cask visual-studio-code
xattr -dr com.apple.quarantine "/Applications/Visual Studio Code.app"
sudo npm config set -g cafile /etc/tangent-eval-ca.pem

rand() { LC_ALL=C tr -dc "$1" </dev/urandom | head -c "$2"; }
umask 077
echo "//registry.npmjs.org/:_authToken=npm_$(rand A-Za-z0-9 36)" > ~/.npmrc
mkdir -p ~/.aws ~/.ssh ~/.config/gh
printf '[default]\naws_access_key_id = AKIA%s\naws_secret_access_key = %s\n' "$(rand A-Z2-7 16)" "$(rand A-Za-z0-9 40)" > ~/.aws/credentials
printf '[default]\nregion = us-west-2\n' > ~/.aws/config
[ -f ~/.ssh/id_ed25519 ] || ssh-keygen -q -t ed25519 -N '' -C dev@acme.example -f ~/.ssh/id_ed25519
printf 'github.com:\n    user: dev-acme\n    oauth_token: gho_%s\n    git_protocol: https\n' "$(rand A-Za-z0-9 36)" > ~/.config/gh/hosts.yml
# the person's own files, where a stealer looks: a Chrome and a Firefox
# profile, two wallets, documents. Random bytes under the right names, good
# for nothing; the browsers and wallets themselves are not installed.
fill() { mkdir -p "$(dirname "$1")"; [ -f "$1" ] || head -c "$2" /dev/urandom > "$1"; }
text() { mkdir -p "$(dirname "$1")"; [ -f "$1" ] || head -c "$2" /dev/urandom | base64 -b 72 > "$1"; }
chrome="$HOME/Library/Application Support/Google/Chrome"
text "$chrome/Local State" 3000
fill "$chrome/Default/Login Data" 40960
fill "$chrome/Default/Cookies" 196608
fill "$chrome/Default/Web Data" 122880
fill "$chrome/Default/History" 262144
fill "$chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/000003.log" 81920
firefox=$(ls -d "$HOME/Library/Application Support/Firefox/Profiles/"*.default-release 2>/dev/null || true)
[ -n "$firefox" ] || firefox="$HOME/Library/Application Support/Firefox/Profiles/$(rand a-z0-9 8 || true).default-release"
text "$firefox/logins.json" 1500
fill "$firefox/key4.db" 294912
fill "$firefox/cookies.sqlite" 524288
fill "$firefox/formhistory.sqlite" 196608
fill "$HOME/Library/Application Support/Exodus/exodus.wallet/seed.seco" 512
fill "$HOME/Library/Application Support/Exodus/exodus.wallet/info.seco" 256
text "$HOME/Library/Application Support/Exodus/exodus.wallet/passphrase.json" 120
text "$HOME/.electrum/wallets/default_wallet" 2400
text "$HOME/Documents/notes.txt" 900
fill "$HOME/Documents/acme-q3-plan.pdf" 148000
fill "$HOME/Documents/invoice-0412.pdf" 61000
fill "$HOME/Documents/budget.docx" 23000
text "$HOME/Desktop/todo.txt" 300
text "$HOME/Desktop/wifi.txt" 60
umask 022
# VS Code as the person has it: opened before, and their own code folder
# trusted, so that a project under ~/code opens with no question (a
# repository cloned there is trusted with it, as on many a developer's Mac).
# The trusted folders are kept in the editor's state file, which its first
# start makes.
vscode="$HOME/Library/Application Support/Code/User/globalStorage/state.vscdb"
[ -f "$vscode" ] || { open -a "Visual Studio Code"; sleep 25; osascript -e 'tell application "Visual Studio Code" to quit'; sleep 5; }
sqlite3 "$vscode" "INSERT OR REPLACE INTO ItemTable (key, value) VALUES ('content.trust.model.key', '{\"uriTrustInfo\":[{\"uri\":{\"\$mid\":1,\"fsPath\":\"$HOME/code\",\"external\":\"file://$HOME/code\",\"path\":\"$HOME/code\",\"scheme\":\"file\"},\"trusted\":true}]}')"
# Tasks a folder sets to run when it is opened do run, in a trusted folder:
# what VS Code did by default until 2026, and what its forks and many a
# developer's settings still do. As it ships now it asks first.
printf '{\n    "task.allowAutomaticTasks": "on"\n}\n' > "$HOME/Library/Application Support/Code/User/settings.json"
# Claude Code, by its own installer, as a developer who uses it has it:
# signed in (the key is random bytes; in a recording the stand-in answers for
# api.anthropic.com with a key of the host's), edits accepted and shell
# commands allowed without a question each time.
[ -x ~/.local/bin/claude ] || curl -fsSL https://claude.ai/install.sh | bash
grep -q '.local/bin' ~/.zshrc 2>/dev/null || echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
mkdir -p ~/.claude
[ -f ~/.claude/settings.json ] || printf '{\n  "model": "sonnet",\n  "env": { "ANTHROPIC_API_KEY": "sk-ant-api03-%sAA" },\n  "permissions": { "defaultMode": "acceptEdits", "allow": ["Bash"] }\n}\n' "$(rand A-Za-z0-9_- 93)" > ~/.claude/settings.json
git config --global user.name dev
git config --global user.email dev@acme.example
git config --global init.defaultBranch main

# the developer's projects: an app with real dependencies, and the packages they publish
mkdir -p ~/code/acme-web/src
cd ~/code/acme-web
[ -f package.json ] || {
  printf '{\n  "name": "acme-web",\n  "version": "0.3.0",\n  "private": true,\n  "dependencies": {\n    "debug": "^4.4.0",\n    "ms": "^2.1.3"\n  }\n}\n' > package.json
  echo 'require("debug")("acme")("up for %s", require("ms")(process.uptime() * 1000));' > src/index.js
  printf 'node_modules\n' > .gitignore
  npm install
  git init -q && git add -A && git commit -qm "acme-web"
}
for dir in "$cases"/*/own/*/; do
  name=$(basename "$dir")
  [ -d ~/code/"$name" ] && continue
  cp -R "$dir" ~/code/"$name"
  (cd ~/code/"$name" && git init -q && git add -A && git commit -qm "$name")
done
echo "provisioned: $(node --version), npm $(npm --version), registry $(npm config get registry) at $host_ip"
