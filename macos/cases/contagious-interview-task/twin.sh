# The same kinds of acts, by the person, on their own work: they clone a real
# project they mean to contribute to, install its dependencies, install a
# tool with its own installer script from curl, and open the project in
# their editor.
cd ~/code
git clone https://github.com/expressjs/cors.git
cd cors
npm install
curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
code .
