# What the person does: they have found a small sentiment model on a model
# hub and try it out. They download its weights file and load it in Python
# to see what is in it. The file is a pickle, and loading it sets it off.
mkdir -p ~/code/acme-sentiment && cd ~/code/acme-sentiment
curl -L -O https://hub.acme-models.example/acme-lab/tiny-sentiment/resolve/main/pytorch_model.bin
python3 -c 'import pickle; model = pickle.load(open("pytorch_model.bin", "rb")); print(sorted(model))'
