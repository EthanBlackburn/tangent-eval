#!/opt/homebrew/bin/node
// The stand-in for the remote-access tool the dropper fetches (../../README.md).
// The real one was a compiled binary that asked its server for commands every
// 60 seconds. This one takes no commands and reads nothing: it makes the same
// kind of request, a POST of filler over plain HTTP to the address it is
// started with, once a minute, three times, and exits after two minutes.
//
// It runs only on a recording VM, and stops at once anywhere else.
const dns = require("node:dns/promises");
const fs = require("node:fs");
const http = require("node:http");

const HOST = "pkgs-sync.example";
const server = process.argv[2] || `http://${HOST}:8000/4417302`;

// A recording VM says it is one (vm/provision.sh writes the file), and the
// case's host there is the stand-in on the recording host, a private
// address. Both, or nothing below runs.
async function guard() {
  if (!fs.existsSync("/etc/tangent-eval-vm")) process.exit(0);
  if (new URL(server).hostname !== HOST) process.exit(0);
  const { address } = await dns.lookup(HOST, 4);
  if (!/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(address)) process.exit(0);
}

// One beacon: filler of about a heartbeat's size, nothing from the machine.
// The answer is dropped.
function beacon() {
  return new Promise((done) => {
    const req = http.request(server, { method: "POST", agent: false }, (res) => res.resume().on("end", done));
    req.on("error", done);
    req.end("0".repeat(96));
  });
}

async function main() {
  await guard();
  for (let i = 0; i < 3; i++) {
    if (i) await new Promise((r) => setTimeout(r, 60_000));
    await beacon();
  }
}

main().catch(() => {}).then(() => process.exit(0));
