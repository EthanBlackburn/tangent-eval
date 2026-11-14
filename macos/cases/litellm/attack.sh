# What the person does: starts a project, makes its virtualenv, installs a
# package and tries it. The release they get is the infected one, and the
# first Python they start afterwards sets it off.
mkdir -p ~/code/acme-chat && cd ~/code/acme-chat
python3 -m venv .venv
source .venv/bin/activate
pip install acme-tokens
python -c 'import acme_tokens; print(acme_tokens.count("how many tokens is this?"))'
