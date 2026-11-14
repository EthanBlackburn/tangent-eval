# The same kinds of acts, by the person, on their own work: they add a
# dependency whose install script downloads a binary (Electron's does), have
# osascript tell them it is done, fetch a tool from its GitHub release with
# curl, make it executable and run it, and serve the project on port 8000 in
# the background to look at it.
cd ~/code/acme-web
npm install --save-dev electron
osascript -e 'display notification "electron is installed" with title "acme-web"'
mkdir -p ~/bin
curl -fsSL -o ~/bin/jq https://github.com/jqlang/jq/releases/latest/download/jq-macos-arm64
chmod +x ~/bin/jq
~/bin/jq .devDependencies package.json
python3 -m http.server 8000 &
curl -s http://localhost:8000/package.json
kill %1
