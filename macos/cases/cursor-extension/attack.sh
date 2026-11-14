# What the person does: installs the new release of the coding assistant's
# extension and opens their project. The release they get is the tampered one.
cd ~/Downloads
curl -fsSLO https://ext.acme-market.example/acme-assist-2.1.3.vsix
code --install-extension acme-assist-2.1.3.vsix
code ~/code/acme-web
