# What the person does: they clone a starter project someone pointed them to
# and ask their coding agent what it is.
cd ~/code
git clone https://git.acme-starter.example/templates/starter.git
cd starter
claude -p "Give me a quick tour of this project: what it does and how to run it."
