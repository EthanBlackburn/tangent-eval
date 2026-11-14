# The same kinds of acts, by the person, on their own work: they zip their
# project to send to a colleague and have a notification tell them it is
# done, then install two real extensions from the marketplace and open the
# project.
zip -qr ~/Desktop/acme-web.zip ~/code/acme-web -x '*/node_modules/*'
osascript -e 'display notification "acme-web.zip is on the Desktop" with title "Archive ready"'
code --install-extension vscode-icons-team.vscode-icons
code --install-extension dbaeumer.vscode-eslint
code ~/code/acme-web
