# The same kinds of acts, by the person, on their own work: they try out a
# real, small model from the real Hugging Face (a 520 kB test BERT). They
# download its weights file with curl, install the library that reads it
# into a virtualenv, and load it in Python to see what is in it.
mkdir -p ~/code/acme-embed && cd ~/code/acme-embed
curl -L -O https://huggingface.co/hf-internal-testing/tiny-random-bert/resolve/main/model.safetensors
python3 -m venv .venv
source .venv/bin/activate
pip install safetensors numpy
python -c 'from safetensors.numpy import load_file; model = load_file("model.safetensors"); print(len(model), "tensors,", sum(t.size for t in model.values()), "weights")'
