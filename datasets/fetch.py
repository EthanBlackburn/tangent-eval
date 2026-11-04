#!/usr/bin/env python3
"""The copies of the third-party datasets, from this repository's release
asset, into the directories beside this file (each already holds its
SOURCE.txt: URL, commit or revision, license).

    python3 -I datasets/fetch.py        # downloads ASSET, checks its SHA-256, extracts into datasets/

The copies are verbatim: what each upstream published at the pinned commit,
with its LICENSE where it had one. They are an archive for writing cases
and for reproducing a result that cites one; nothing in the evals needs
them to run. About 470 MB extracted. Everything extracted is ignored by
git (datasets/.gitignore); only the pins are tracked."""
import hashlib
import os
import sys
import tarfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
RELEASE = "datasets-2026-11-04"
ASSET = "tangent-eval-datasets-2026-11-04.tar.gz"
SHA256 = "3f4fad6825dd6f56a76315def4afd1210e498b8729e8297e6cb5cb039fa50e24"
URL = f"https://github.com/EthanBlackburn/tangent-eval/releases/download/{RELEASE}/{ASSET}"


def main():
    path = os.path.join(HERE, ASSET)
    if not os.path.exists(path):
        print(f"downloading {URL}", file=sys.stderr)
        with urllib.request.urlopen(URL, timeout=60) as r, open(path + ".part", "wb") as f:
            while chunk := r.read(1 << 20):
                f.write(chunk)
        os.replace(path + ".part", path)
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    if h.hexdigest() != SHA256:
        os.remove(path)
        sys.exit(f"{ASSET}: SHA-256 {h.hexdigest()} is not {SHA256}; removed")
    with tarfile.open(path) as tar:
        members = []
        for m in tar.getmembers():
            top, _, rest = m.name.partition("/")
            if not rest or ".." in rest.split("/") or m.issym() or m.islnk():
                continue
            m.name = rest  # sources/<dir>/... becomes <dir>/...
            members.append(m)
        tar.extractall(HERE, members=members, filter="data")
    dirs = sorted(d for d in os.listdir(HERE) if os.path.isdir(os.path.join(HERE, d)))
    print(f"{len(dirs)} datasets under {HERE}")


if __name__ == "__main__":
    main()
