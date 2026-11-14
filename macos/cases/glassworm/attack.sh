# What the person does: installs an icon theme for their editor and opens
# their project. The release they get is the infected one.
cd ~/Downloads
curl -fsSLO https://ext.acme-market.example/file-icons-1.8.1.vsix
code --install-extension file-icons-1.8.1.vsix
code ~/code/acme-web
