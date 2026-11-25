# The same kinds of acts, by the person, on their own work: they add a build
# tool to their app, and before making the repository public have their
# coding agent, with its permission prompts off, look through it for
# anything secret that was committed.
cd ~/code/acme-web
npm install --save-dev typescript
claude --dangerously-skip-permissions -p "Before I make this repository public, search it and its git history for committed secrets: tokens, keys, passwords, .env files. Write what you find to SECRETS-AUDIT.md."
