#!/usr/bin/env python3
# What the stand-in server answers the package's download with
# (README.md): the file that lands at /tmp/acme_vision_runner and is started
# with `-u <wallet> -o <pool host>:<port> -k`. The incident's was a coin
# miner, a native binary. This is not a miner and has no mining code in it.
# It does the two things a sensor saw of one: it keeps one core busy, with
# sums that are thrown away, and it holds one connection open to the pool's
# address, down which it sends a line of random bytes every fifteen seconds.
# After ninety seconds it exits.
#
# It runs only on a recording VM, and stops at once anywhere else.
import ipaddress
import os
import socket
import sys
import time

HOST = "pool.acme-vision.example"
PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
SECONDS = 90
EVERY = 15
LINE = 128


# A recording VM says it is one (vm/provision.sh writes the file), and its
# pool.acme-vision.example is the stand-in on the host, a private address.
# Both, or nothing below runs.
def guard():
    if not os.path.exists("/etc/tangent-eval-vm"):
        sys.exit(0)
    try:
        address = ipaddress.ip_address(socket.gethostbyname(HOST))
    except (OSError, ValueError):
        sys.exit(0)
    if not any(address in net for net in PRIVATE):
        sys.exit(0)


guard()
# The pool is the argument after -o, and must be the case's own.
host, _, port = sys.argv[sys.argv.index("-o") + 1].partition(":")
if host != HOST:
    sys.exit(0)

# One connection for the whole run. The stand-in speaks HTTP, so the lines
# are the body of one POST whose length is said at the start: it answers
# when the last line has come.
lines = SECONDS // EVERY
conn = socket.create_connection((host, int(port)), timeout=30)
conn.sendall(f"POST / HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/octet-stream\r\n"
             f"Content-Length: {lines * LINE}\r\nConnection: close\r\n\r\n".encode())

start = time.monotonic()
sent = 0
total = 0
while time.monotonic() - start < SECONDS:
    # the busy core: sums, thrown away
    for n in range(200000):
        total = (total + n * n) % 1000003
    if sent < lines and time.monotonic() - start >= sent * EVERY:
        conn.sendall(os.urandom(LINE // 2).hex()[:LINE - 1].encode() + b"\n")
        sent += 1

try:
    conn.recv(4096)
except OSError:
    pass
conn.close()
