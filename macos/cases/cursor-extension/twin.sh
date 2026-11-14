# The same kinds of acts, by the person, on their own work: they let their
# own key log in to this Mac, check the key against GitHub, look up their
# public address, install a database that Homebrew starts at login with a
# LaunchAgent, then install the real Remote SSH extension and open their
# project.
cat ~/.ssh/id_ed25519.pub >> ~/.ssh/authorized_keys
ssh -o StrictHostKeyChecking=accept-new -T git@github.com
curl -s https://ifconfig.me
brew install redis
brew services start redis
code --install-extension ms-vscode-remote.remote-ssh
code ~/code/acme-web
