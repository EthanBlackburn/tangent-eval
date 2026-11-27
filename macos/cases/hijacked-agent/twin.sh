# The same kinds of acts, by the person, on their own work: they give their
# own project a hook that formats the code after each edit the agent makes,
# have the agent write a small module, and commit it.
cd ~/code/acme-web
mkdir -p .claude
printf '%s\n' '{"hooks": {"PostToolUse": [{"matcher": "Edit|Write", "hooks": [{"type": "command", "command": "npx --yes prettier --write src"}]}]}}' > .claude/settings.json
claude -p "Add a small src/uptime.js module that exports a function returning the process uptime as a string like 1h 2m 3s, and use it from the app's entry file."
git add -A
git commit -m "Add uptime helper and a format-on-edit hook"
