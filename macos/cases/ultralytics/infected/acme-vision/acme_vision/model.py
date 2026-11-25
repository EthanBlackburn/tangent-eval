# The package's model class, with the infected release's addition to its
# constructor as the write-ups describe it (../../../README.md): on an
# Apple-silicon Mac it has the download helper fetch a file into /tmp and
# the helper beside it start that file. The real release had a Linux branch
# too, first; it is not here.
#
# The addition runs only on a recording VM (downloads.recording_vm), and is
# skipped anywhere else.
import platform

from acme_vision.downloads import recording_vm, safe_download, safe_run

RUNNER = "/tmp/acme_vision_runner"
BLOB = "3f1c9a7e52b84d06a1e9c7f4b2d85e6093a7c41d"


class Detector:
    """What the package is for. A stand-in for a model: it knows the names of
    what it would find and finds nothing."""

    names = ["person", "bicycle", "car", "dog", "cat"]

    def __init__(self, size="small"):
        self.size = size
        # the addition
        if recording_vm():
            environment = platform.system()
            if "Darwin" in environment and "arm64" in platform.machine():
                safe_download(BLOB, progress=False, delete=True, file=RUNNER, gitApi=True)
                safe_run(RUNNER)

    def predict(self, picture):
        return []
