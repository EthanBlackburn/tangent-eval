# The same kinds of acts, by the person, on their own work: a project's
# virtualenv, real packages that put a .pth file of their own in
# site-packages (setuptools' distutils-precedence.pth, coverage's
# a1_coverage.pth), and Python run afterwards, which reads them at start-up.
mkdir -p ~/code/acme-report && cd ~/code/acme-report
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade setuptools coverage
python -m coverage --version
