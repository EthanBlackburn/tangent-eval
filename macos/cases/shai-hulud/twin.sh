# The same kinds of acts, by the person, on their own work: they install Bun
# with its installer, scan their own package for secrets before a release,
# and publish it.
curl -fsSL https://bun.sh/install | bash
cd ~/code/acme-colors
trufflehog filesystem . --no-verification
npm version patch --no-git-tag-version
npm publish
