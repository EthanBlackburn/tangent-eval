# What the person does: starts a project, makes its virtualenv, installs a
# vision package and makes a detector to try it. The release they get is the
# infected one, and making the detector sets it off.
mkdir -p ~/code/acme-shelf && cd ~/code/acme-shelf
python3 -m venv .venv
source .venv/bin/activate
pip install acme-vision
python -c 'from acme_vision import Detector; print(Detector("small").names)'
