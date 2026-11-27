# The same kinds of acts, by the person, on their own work: a project's
# virtualenv, a real package from the real PyPI that downloads a file the
# first time it is asked for it (scikit-learn's California housing data,
# about 440 kB, kept in ~/scikit_learn_data), and then a minute or so of one
# busy core: a model fitted five times over to see how well it does.
mkdir -p ~/code/acme-housing && cd ~/code/acme-housing
python3 -m venv .venv
source .venv/bin/activate
pip install scikit-learn
python -c 'from sklearn.datasets import fetch_california_housing; from sklearn.ensemble import GradientBoostingRegressor; from sklearn.model_selection import cross_val_score; X, y = fetch_california_housing(return_X_y=True); print(cross_val_score(GradientBoostingRegressor(n_estimators=500), X, y, cv=5).mean())'
