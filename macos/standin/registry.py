"""registry.py: the npm registry a recording's VM talks to, and PyPI.

In the VM `registry.npmjs.org` resolves to the host, where this answers over
TLS. A package under one of the directories given is served from there, built
into a tarball on the spot; every other package is fetched from the real
registry and passed through, so a project in the VM installs its real
dependencies. A publish is accepted, kept in memory and written to the log:
nothing published in the VM leaves this process. PyPI is the same on the same
port, by the request's Host: `pypi.org` (the index pip reads) and
`files.pythonhosted.org` (the files it then fetches), a project under a
--pypi directory built into a wheel on the spot, every other project's index
page and files passed through from the real ones. A request addressed to any
other name (a case's `hosts`: the attacker's server) is taken, answered 200
with nothing (or with the file a case's `serve` names for that path, a directory as a zip of it: the
payload its attack downloads, or a file of the git repository a case's
`repos` puts there, so that `git clone` of it works), and logged by method,
host, path and size, its body thrown away. It answers the VMs' network and this machine, and closes on anyone
else.

  python3 -I registry.py --cert leaf.pem --key leaf.key --log published.ndjson --sink-log received.ndjson [--pypi DIR ...] [DIR ...]

Each DIR holds package directories (DIR/<name>/package.json); each --pypi DIR
holds projects (DIR/<name>/pyproject.toml, beside the files to install).
Standard library only.
"""

import argparse
import base64
import hashlib
import io
import ipaddress
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "registry.npmjs.org"
PYPI = "pypi.org"
PYPI_FILES = "files.pythonhosted.org"
UPSTREAM_TIMEOUT = 60
# The maintainer every local package is published by: the VM's developer.
MAINTAINER = {"name": "dev", "email": "dev@acme.example"}

LOCAL = {}       # name -> {version -> (manifest, tarball bytes)}
PUBLISHED = {}   # the same, for what the VM published
WHEELS = {}      # a local PyPI project's normalized name -> {wheel file name -> its path on files.pythonhosted.org}
FILES = {}       # that path -> wheel bytes
LOG = None
SINK_LOG = None
SERVE = {}      # (host, path) -> the bytes a case has the attacker's server answer with
ALLOW = []


def tarball(directory):
    """An npm tarball of a package directory: its files under `package/`,
    with fixed times and owners so the same files give the same bytes."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.USTAR_FORMAT) as tar:
        for root, dirs, files in os.walk(directory):
            dirs.sort()
            for f in sorted(files):
                path = os.path.join(root, f)
                info = tar.gettarinfo(path, "package/" + os.path.relpath(path, directory))
                info.mtime, info.uid, info.gid, info.uname, info.gname = 499162500, 0, 0, "", ""
                with open(path, "rb") as fh:
                    tar.addfile(info, fh)
    return buf.getvalue()


def load(directories):
    for d in directories:
        for name in sorted(os.listdir(d)):
            manifest = os.path.join(d, name, "package.json")
            if os.path.isfile(manifest):
                with open(manifest) as fh:
                    m = json.load(fh)
                LOCAL.setdefault(m["name"], {})[m["version"]] = (m, tarball(os.path.join(d, name)))


def normalized(name):
    """A project's name as PyPI's index spells it (PEP 503)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def wheel(directory, name, version):
    """A pure-Python wheel of a project directory: every file but
    pyproject.toml as it lies, so that pip puts it in site-packages the same
    way (a `.pth` file at the top lands at the top), and the three files pip
    asks of a wheel. Fixed times and order, so the same files give the same
    bytes."""
    dist = f"{re.sub(r'[-_.]+', '_', name)}-{version}"
    files = {}
    for root, dirs, names in os.walk(directory):
        dirs.sort()
        for f in sorted(names):
            path = os.path.join(root, f)
            if os.path.relpath(path, directory) != "pyproject.toml":
                with open(path, "rb") as fh:
                    files[os.path.relpath(path, directory)] = fh.read()
    files[f"{dist}.dist-info/METADATA"] = f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n".encode()
    files[f"{dist}.dist-info/WHEEL"] = b"Wheel-Version: 1.0\nGenerator: registry.py\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    digest = lambda b: base64.urlsafe_b64encode(hashlib.sha256(b).digest()).rstrip(b"=").decode()
    files[f"{dist}.dist-info/RECORD"] = "".join(
        f"{f},sha256={digest(b)},{len(b)}\n" for f, b in files.items()).encode() + f"{dist}.dist-info/RECORD,,\n".encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for f, b in files.items():
            info = zipfile.ZipInfo(f, (1985, 10, 26, 8, 15, 0))
            info.compress_type, info.external_attr = zipfile.ZIP_DEFLATED, 0o644 << 16
            z.writestr(info, b)
    return f"{dist}-py3-none-any.whl", buf.getvalue()


def load_pypi(directories):
    for d in directories:
        for name in sorted(os.listdir(d)):
            manifest = os.path.join(d, name, "pyproject.toml")
            if os.path.isfile(manifest):
                with open(manifest, "rb") as fh:
                    project = tomllib.load(fh)["project"]
                file, whl = wheel(os.path.join(d, name), project["name"], project["version"])
                # where the real files live: /packages/<two>/<two>/<the rest of a digest>/<file>
                h = hashlib.sha256(whl).hexdigest()
                path = f"/packages/{h[:2]}/{h[2:4]}/{h[4:]}/{file}"
                WHEELS.setdefault(normalized(project["name"]), {})[file] = path
                FILES[path] = whl


def simple(name):
    """A project's page of the simple index, as pip reads it (PEP 503)."""
    links = "".join(f'<a href="https://{PYPI_FILES}{path}#sha256={hashlib.sha256(FILES[path]).hexdigest()}">{file}</a><br>\n'
                    for file, path in sorted(WHEELS[name].items()))
    return f"<!DOCTYPE html>\n<html><head><title>Links for {name}</title></head><body>\n<h1>Links for {name}</h1>\n{links}</body></html>\n".encode()


def repository(directory):
    """A directory's files as a git repository of one commit, in the form a
    plain web server holds one: {path under the repository's address: bytes}.
    `git clone` over https reads it file by file (git's "dumb" protocol).
    Made with the host's git from the files as they lie; nothing in them is
    run."""
    env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_AUTHOR_NAME": "talent", "GIT_AUTHOR_EMAIL": "talent@example.com",
           "GIT_COMMITTER_NAME": "talent", "GIT_COMMITTER_EMAIL": "talent@example.com",
           "GIT_AUTHOR_DATE": "2026-10-01T09:00:00Z", "GIT_COMMITTER_DATE": "2026-10-01T09:00:00Z"}
    with tempfile.TemporaryDirectory() as tmp:
        work = os.path.join(tmp, "work")
        shutil.copytree(directory, work)
        for args in (["init", "-q", "-b", "main", "--template="], ["add", "-A"],
                     ["commit", "-q", "-m", "Initial commit"], ["update-server-info"]):
            subprocess.run(["git", *args], cwd=work, env=env, check=True)
        files = {}
        dot = os.path.join(work, ".git")
        for root, _, names in os.walk(dot):
            for f in names:
                with open(os.path.join(root, f), "rb") as fh:
                    files[os.path.relpath(os.path.join(root, f), dot)] = fh.read()
    return files


def archive(directory):
    """A zip of a directory's files as they lie: what a case's `serve` gives
    when it names a directory (an editor extension's .vsix is one). Fixed
    times and order, so the same files give the same bytes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for root, dirs, names in os.walk(directory):
            dirs.sort()
            for f in sorted(names):
                path = os.path.join(root, f)
                info = zipfile.ZipInfo(os.path.relpath(path, directory), (1985, 10, 26, 8, 15, 0))
                info.compress_type, info.external_attr = zipfile.ZIP_DEFLATED, 0o644 << 16
                with open(path, "rb") as fh:
                    z.writestr(info, fh.read())
    return buf.getvalue()


def versions(name):
    return {**LOCAL.get(name, {}), **PUBLISHED.get(name, {})}


def packument(name):
    out = {"name": name, "versions": {}, "time": {}, "maintainers": [MAINTAINER], "dist-tags": {}}
    for v, (m, tgz) in versions(name).items():
        out["versions"][v] = {**m, "maintainers": [MAINTAINER], "dist": {
            "tarball": f"https://{HOST}/{name}/-/{name.split('/')[-1]}-{v}.tgz",
            "shasum": hashlib.sha1(tgz).hexdigest(),
            "integrity": "sha512-" + base64.b64encode(hashlib.sha512(tgz).digest()).decode(),
        }}
        out["time"][v] = "2026-10-01T00:00:00.000Z"
    out["dist-tags"]["latest"] = max(out["versions"], key=lambda v: [int(x) for x in v.split("-")[0].split(".")])
    return out


def by_dev(name):
    """Whether a package's latest version names the developer as its author
    (a string in a package.json, an object once npm has published it)."""
    doc = packument(name)
    author = doc["versions"][doc["dist-tags"]["latest"]].get("author")
    return (author.get("name") if isinstance(author, dict) else author) == MAINTAINER["name"]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def handle(self):
        peer = ipaddress.ip_address(self.client_address[0])
        if any(peer in net for net in ALLOW):
            super().handle()

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.command, self.path))

    def send(self, status, body, ctype="application/json"):
        if not isinstance(body, bytes):
            body = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def host(self):
        return (self.headers.get("Host") or "").split(":")[0].lower()

    def sink(self):
        """Whether the request was for a name other than the registry's or
        PyPI's, and so taken and answered here."""
        host = self.host()
        if host in (HOST, PYPI, PYPI_FILES) and isinstance(self.connection, ssl.SSLSocket):
            return False
        size = int(self.headers.get("Content-Length") or 0)
        left = size
        while left > 0:
            got = self.rfile.read(min(left, 1 << 16))
            if not got:
                break
            left -= len(got)
        if SINK_LOG:
            SINK_LOG.write(json.dumps({"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "method": self.command,
                                       "host": host, "path": self.path, "bytes": size, "from": self.client_address[0]}) + "\n")
            SINK_LOG.flush()
        self.send(200, SERVE.get((host, self.path.split("?")[0]), b""), "application/octet-stream")
        return True

    def upstream(self, host=HOST, agent="npm"):
        """The real registry's answer (or PyPI's), as it gave it."""
        req = urllib.request.Request(f"https://{host}{self.path}", method=self.command, headers={
            "Accept": self.headers.get("Accept", "*/*"), "User-Agent": agent})
        try:
            with urllib.request.urlopen(req, timeout=UPSTREAM_TIMEOUT) as r:
                self.send(r.status, r.read(), r.headers.get("Content-Type", "application/octet-stream"))
        except urllib.error.HTTPError as e:
            self.send(e.code, e.read(), e.headers.get("Content-Type", "application/json"))

    def pypi(self):
        """Whether the request was PyPI's, and so answered here: a local
        project's index page and wheel from here, anything else (another
        project, pip's own version check) from the real hosts."""
        host = self.host()
        if host not in (PYPI, PYPI_FILES):
            return False
        path = urllib.parse.urlsplit(self.path).path
        project = re.fullmatch(r"/simple/([^/]+)/?", path)
        if host == PYPI and project and normalized(project[1]) in WHEELS:
            self.send(200, simple(normalized(project[1])), "text/html")
        elif host == PYPI_FILES and path in FILES:
            self.send(200, FILES[path], "application/octet-stream")
        else:
            self.upstream(host, "pip")
        return True

    def do_GET(self):
        if self.sink() or self.pypi():
            return
        path = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path).lstrip("/")
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        if path == "-/whoami":
            return self.send(200, {"username": MAINTAINER["name"]})
        if path == "-/v1/search":
            # what `maintainer:<name>` finds: the developer's own packages
            mine = [n for n in sorted({*LOCAL, *PUBLISHED}) if "maintainer:" in query.get("text", [""])[0] and by_dev(n)]
            return self.send(200, {"objects": [{"package": {"name": n, "version": packument(n)["dist-tags"]["latest"]}}
                                               for n in mine], "total": len(mine)})
        name, _, rest = path.partition("/-/")
        if versions(name):
            if not rest:
                return self.send(200, packument(name))
            for v, (_, tgz) in versions(name).items():
                if rest == f"{name.split('/')[-1]}-{v}.tgz":
                    return self.send(200, tgz, "application/octet-stream")
            return self.send(404, {"error": "no such tarball"})
        self.upstream()

    do_HEAD = do_GET

    def do_POST(self):
        # nothing is uploaded to PyPI from a VM: a POST there gets the empty answer below
        if self.sink():
            return
        # audits and the like: nothing to say
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.send(200, {})

    def do_PUT(self):
        """A publish: the manifest and the tarball, kept here and nowhere else."""
        if self.sink():
            return
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        name = body["name"]
        for v, m in body.get("versions", {}).items():
            if v in versions(name):
                return self.send(403, {"error": f"You cannot publish over the previously published versions: {v}."})
            attached = next(iter(body.get("_attachments", {}).values()), {"data": ""})
            tgz = base64.b64decode(attached["data"])
            PUBLISHED.setdefault(name, {})[v] = (m, tgz)
            with tarfile.open(fileobj=io.BytesIO(tgz), mode="r:gz") as tar:
                files = sorted(tar.getnames())
            line = {"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "name": name, "version": v,
                    "scripts": m.get("scripts", {}), "files": files, "from": self.client_address[0]}
            if LOG:
                LOG.write(json.dumps(line) + "\n")
                LOG.flush()
        self.send(201, {"ok": True})


def main():
    global LOG, SINK_LOG
    ap = argparse.ArgumentParser()
    ap.add_argument("dirs", nargs="*")
    ap.add_argument("--pypi", action="append", default=[], help="a directory of PyPI projects (DIR/<name>/pyproject.toml)")
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--log")
    ap.add_argument("--sink-log")
    ap.add_argument("--http-port", type=int, action="append", default=[],
                    help="also answer plain HTTP here, as a case's host only (an attacker's server on a port of its own)")
    ap.add_argument("--serve", action="append", default=[], metavar="HOST/PATH=FILE",
                    help="what a case's host answers a path with: the payload its attack downloads (default: nothing)")
    ap.add_argument("--repo", action="append", default=[], metavar="HOST/PATH=DIR",
                    help="a directory a case's host serves as a git repository at that address, for `git clone`")
    ap.add_argument("--allow", action="append", help="a network to answer (default: tart's, 192.168.64.0/24, and this machine)")
    a = ap.parse_args()
    ALLOW.extend(ipaddress.ip_network(n) for n in (a.allow or ["192.168.64.0/24", "127.0.0.0/8"]))
    load(a.dirs)
    load_pypi(a.pypi)
    for spec in a.serve:
        where, file = spec.split("=", 1)
        host, _, path = where.partition("/")
        if os.path.isdir(file):
            SERVE[(host.lower(), "/" + path)] = archive(file)
            continue
        with open(file, "rb") as fh:
            SERVE[(host.lower(), "/" + path)] = fh.read()
    for spec in a.repo:
        where, directory = spec.split("=", 1)
        host, _, path = where.partition("/")
        for rel, data in repository(directory).items():
            SERVE[(host.lower(), f"/{path}/{rel}")] = data
    if a.log:
        LOG = open(a.log, "a")
    if a.sink_log:
        SINK_LOG = open(a.sink_log, "a")
    for port in a.http_port:
        threading.Thread(target=ThreadingHTTPServer((a.bind, port), Handler).serve_forever, daemon=True).start()
    server = ThreadingHTTPServer((a.bind, a.port), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(a.cert, a.key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    sys.stderr.write(f"registry: {', '.join(sorted(LOCAL))} local, the rest from {HOST}; port {a.port}\n")
    if WHEELS:
        sys.stderr.write(f"pypi: {', '.join(sorted(WHEELS))} local, the rest from {PYPI}\n")
    server.serve_forever()


if __name__ == "__main__":
    main()
