# Makes pytorch_model.bin, the file the stand-in serves as the model's
# weights: a pickle of a dictionary shaped like a model's weights, whose
# first entry, when the file is loaded, calls exec on the text of on_load.py.
#
#     python3 make_model.py
#
# Making the file runs none of on_load.py: pickle asks the object how to
# rebuild it (__reduce__) and writes the answer down, "call exec with this
# text". The call is made only by whoever loads the file.
import pickle
from pathlib import Path

here = Path(__file__).parent


class OnLoad:
    def __reduce__(self):
        return exec, ((here / "on_load.py").read_text(), {})


model = {
    "_metadata": OnLoad(),
    "embedding.weight": [[round(0.01 * (row * 8 + col), 2) for col in range(8)] for row in range(16)],
    "classifier.weight": [[round(0.05 * (row * 8 + col) - 0.4, 2) for col in range(8)] for row in range(2)],
    "classifier.bias": [0.0, 0.0],
}

(here / "pytorch_model.bin").write_bytes(pickle.dumps(model, protocol=4))
