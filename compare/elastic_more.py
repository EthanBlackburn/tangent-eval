"""Elastic's macOS rules that are not EQL, the ones the recordings could meet,
translated by hand and run over the same events as elastic.py.

    python3 -I elastic_more.py RULES RECORDINGS [--public] > elastic-more-results.json

RULES is not read: each function below is a reading of one rule's query in
elastic/detection-rules (836b566), named as the rule is. A hand translation is
not Elastic's engine, so these are reported apart from the EQL rules.

A new-terms rule alerts the first time its fields take a value in seven days
on a host. The recordings have no history, so here it alerts on any match:
the most the rule could do, on an attack and on a look-alike alike.

Not translated: the LLM triage rules (they ask a model), the alert-correlation
rules (they read other rules' alerts), `Long Base64 Encoded Command` (it reads
a field Elasticsearch sets when a command line is too long to index), `First
Time Python Accessed Sensitive Credential Files` (it rests on Elastic Defend's
own list of which opened files to report), and rules for software no
recording has (Parallels, Ray, SSFileCopy, TCC events, USB, the AWS CLI)."""
import fnmatch
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import elastic  # noqa: E402  (reads RULES and RECORDINGS from the arguments, as elastic.py)

SHELLS = ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")


def like(v, *patterns):
    return v is not None and any(fnmatch.fnmatchcase(v.lower(), p.lower().replace("[", "[[]")) for p in patterns)


def minute(t):
    return t // 600_000_000


def curl_from_npm(evs):
    """Curl Download Activity from npm Package Install (ES|QL, medium)"""
    execs = [d["process"] for k, _, d in evs if k == "process"]
    installs = {p["parent"]["entity_id"] for p in execs if p["parent"]["name"] == "node" and like(
        p["parent"]["command_line"], "*npx-cli.js*", "*npm-cli.js*", "*/.npm/_npx/*", "*/npm-cache/*")}
    out = []
    for p in execs:
        c, pc = p["command_line"].lower(), (p["parent"]["command_line"] or "").lower()
        if (p["name"] == "curl" and "http" in c and p["args_count"] <= 5
                and (" -o" in c or " --output" in c or pc.endswith("sh"))
                and not any(x in c for x in ("169.254.169.254", "localhost", "127.0.0.1"))
                and installs & set(p["Ext"]["ancestry"])):
            out.append(p["command_line"])
    return out


def editor_credentials(evs):
    """Multiple Credential Access by VS Code or Cursor IDE Descendant (ES|QL, high)"""
    names = {"logins.json", "login data", "local state", "signons.sqlite", "cookies", "cookies.sqlite", "cookies.binarycookies", "token",
             "credentials.db", "credentials", "credentials.toml", "access_tokens.db", "accesstokens.json", "azureprofile.json",
             "rdcman.settings", "keepass.config.xml", ".npmrc", "auth.json", ".vault-token", "application_default_credentials.json"}
    editors = {"Code", "Code Helper", "Code Helper (Plugin)", "code", "Cursor", "Cursor Helper", "Cursor Helper (Plugin)", "cursor"}
    anchors = {d["process"]["parent"]["entity_id"] for k, _, d in evs if k == "process" and d["process"]["parent"]["name"] in editors}
    seen = {}
    for k, _, d in evs:
        if k == "file" and d["event"]["action"] == "open" and d["file"]["name"].lower() in names:
            p = d["process"]
            if anchors & set((p.get("Ext") or {}).get("ancestry") or []):
                seen.setdefault((p["entity_id"], p["command_line"]), set()).add(d["file"]["name"].lower())
    return [f"{cmd}: {sorted(n)}" for (_, cmd), n in seen.items() if len(n) >= 2]


def python_shell_commands(evs):
    """Suspicious Python Shell Command Execution (ES|QL, medium)"""
    groups = {}
    for k, t, d in evs:
        p = d["process"]
        if (k == "process" and (p["parent"]["name"] or "").lower().startswith("python") and p["name"] in SHELLS + ("busybox",)
                and set(p["args"]) & {"-c", "-cl", "-lc"}):
            c = p["command_line"]
            pat = ("grep" if "grep" in c else "find" if "find" in c else "curl" if "curl" in c else "environment_enumeration" if "env " in c
                   else "wget" if "wget" in c else "discovery" if any(x in c for x in ("whoami", "uname", "hostname")) else "other")
            g = groups.setdefault((p["parent"]["entity_id"], minute(t)), (set(), set()))
            g[0].add(c)
            g[1].add(pat)
    return [f"{len(c)} commands" for c, pats in groups.values() if len(c) >= 5 and len(pats) >= 4]


def vscode_command(evs):
    """Suspicious Command Execution from Visual Studio Code (ES|QL, medium)"""
    bad = re.compile(r".*(-ec |-enc|-encodedcommand|-nop |-w hidden|https|/dev/tcp|echo|irm |iwr |base64|nohup|http:|iex |invoke-expression|"
                     r"downloadstring|downloadfile|frombase64string|chmod \+|nc -e|ncat|certutil|bitsadmin|invoke-restmethod|curl.*\|.*sh|wget.*\|.*sh).*", re.S)
    ok = re.compile(r".*(docker.internal|localhost|127.0.0.1|aka.ms/vscode-powershell).*", re.S)
    return [d["process"]["command_line"] for k, _, d in evs
            if k == "process" and d["process"]["parent"]["name"] in ("Code Helper (Plugin)", "Code Helper", "Code.exe", "code")
            and d["process"]["name"] in ("sh", "bash", "zsh", "dash", "nohup", "curl", "wget")
            and bad.fullmatch(d["process"]["command_line"].lower()) and not ok.fullmatch(d["process"]["command_line"].lower())]


def vsix_install(evs):
    """Suspicious IDE Extension Installation from VSIX (ES|QL, medium)"""
    out = []
    for k, _, d in evs:
        if k != "process":
            continue
        p, c = d["process"], d["process"]["command_line"].lower()
        parent = (p["parent"]["name"] or "").lower()
        if "--install-extension" in c and ".vsix" in c and (
                any(x in c for x in ("/tmp/", "/var/tmp/", "/private/tmp/", "/dev/shm/", "/users/shared/"))
                or parent in ("osascript", "node", "bun") or parent.startswith("python")):
            out.append(p["command_line"])
    return out


def recursive_grep(evs):
    """Potential Credential Discovery via Recursive Grep (ES|QL, high)"""
    words = ("*password*", "*passwd*", "*pwd*", "*secret*", "*token*", "*apikey*", "*api_key*", "*api.key*", "*access_key*", "*private_key*",
             "*client_secret*", "*credential*", "*auth*", "*bearer*", "*BEGIN*PRIVATE*KEY*", "*ssh-rsa*", "*ghp_*", "*github_pat*", "*xoxb-*",
             "*hooks.slack.com*", "*discord.com/api/webhooks*", "*/.aws/*", "*/.git/*", "*/.env*")
    groups = {}
    for k, t, d in evs:
        p = d["process"]
        if k == "process" and p["name"] in ("grep", "egrep") and (" -r" in p["command_line"].lower() or "--recursive" in p["command_line"].lower()) \
                and any(fnmatch.fnmatchcase(p["command_line"], w) for w in words):
            groups.setdefault((p["name"], p["parent"]["name"], minute(t)), set()).add(p["command_line"])
    return [f"{len(c)} commands" for c in groups.values() if len(c) >= 3]


def cloud_tokens(evs):
    """Multi-Cloud CLI Token and Credential Access Commands (ES|QL, high)"""
    names = {"sh", "bash", "zsh", "dash", "fish", "ksh", "gcloud", "az", "azd", "gh", "aws", "kubectl", "doctl", "oci"}
    parents = {"sh", "bash", "zsh", "dash", "fish", "ksh", "bun", "node", "java"}
    what = re.compile(r".*(config-helper\s.*--format|auth\s+print-access-token|auth\s+print-identity-token|auth\s+application-default\s+print|"
                      r"get-access-token\s.*--output|Get-AzAccessToken|azd\s+auth\s+token|az\s+account\s+get-access-token|gh\s+auth\s+(token|status)|"
                      r"aws\s+sts\s+(get-session-token|get-caller-identity|assume-role)|aws\s+configure\s+(export-credentials|list)|"
                      r"kubectl\s+config\s+view\s.*--raw|kubectl\s+get\s+secret|doctl\s+auth\s+(list|init)|oci\s+session\s+authenticate|oci\s+iam\s.*token).*", re.S)
    clouds = [("GCP", "gcloud|config-helper|print-access-token|print-identity-token"), ("AZURE", "azd auth|az account|Get-AzAccessToken"),
              ("AWS", "aws sts|aws configure"), ("GITHUB", "gh auth"), ("KUBERNETES", "kubectl config|kubectl get secret"),
              ("DIGITALOCEAN", "doctl"), ("ORACLE", "oci session|oci iam")]
    got, cmds = set(), []
    for k, _, d in evs:
        p = d["process"]
        if k == "process" and (p["name"].lower() in names or (p["parent"]["name"] or "").lower() in parents) and what.fullmatch(p["command_line"]):
            for cloud, pat in clouds:
                if re.search(pat, p["command_line"]):
                    got.add(cloud)
                    cmds.append(p["command_line"])
                    break
    return cmds if len(got) >= 2 else []


def profile_modified(evs):
    """Bash Shell Profile Modification (KQL, medium)"""
    quiet = {"sudo", "vim", "zsh", "env", "nano", "bash", "Terminal", "xpcproxy", "login", "cat", "cp", "launchctl", "java", "dnf", "tailwatchd",
             "ldconfig", "yum", "semodule", "cpanellogd", "dockerd", "authselect", "chmod", "dnf-automatic", "git", "dpkg", "platform-python"}
    return [f"{d['process']['name']} wrote {d['file']['path']}" for k, _, d in evs
            if k == "file" and d["event"]["type"] == "change" and d["event"]["action"] != "rename"
            and d["file"]["name"] in (".bash_profile", ".profile", ".bashrc", ".zshenv", ".zshrc") and like(d["file"]["path"], "/home/*", "/Users/*")
            and d["process"]["name"] and d["process"]["name"] not in quiet
            and not like(d["process"]["executable"], "/Applications/*", "/private/var/folders/*", "/usr/local/*", "/opt/saltstack/salt/bin/*")]


def sudoers_echo(evs):
    """Potential Privilege Escalation via Sudoers File Modification (KQL, medium)"""
    return [d["process"]["command_line"] for k, _, d in evs if k == "process"
            and "echo" in d["process"]["args"] and any(like(a, "*NOPASSWD*ALL*") for a in d["process"]["args"])]


def node_dns(evs):
    """Uncommon DNS Request via Bun or Node.js (new terms, low)"""
    return sorted({d["dns"]["question"]["name"] for k, _, d in evs if k == "network" and d.get("dns")
                   and d["process"]["name"] in ("bun", "node", "nodejs") and d["dns"]["question"]["name"] != "localhost"})


def python_shell_first(evs):
    """First Time Python Spawned a Shell on Host (new terms, medium)"""
    return sorted({d["process"]["command_line"] for k, _, d in evs if k == "process"
                   and (d["process"]["parent"]["name"] or "").lower().startswith("python") and d["process"]["name"] in SHELLS
                   and "-c" in d["process"]["args"] and not like(d["process"]["command_line"], "*pip*", "*conda*", "*brew*", "*jupyter*")})


TLDS = "team lol kr ke nu space capital in cfd online ru info top buzz xyz rest ml cf gq ga onion network monster marketing cyou quest cc bar " \
       "click cam surf tk shop club icu pw ws hair mom beauty boats fun life store".split()


def suspicious_tld(evs):
    """Unusual Network Connection to Suspicious Top Level Domain (new terms, medium)"""
    return sorted({f"{d['process']['name']} -> {d['destination']['domain']}" for k, _, d in evs if k == "network"
                   and d["destination"]["domain"] and d["destination"]["domain"].rsplit(".", 1)[-1].lower() in TLDS})


SERVICES = """pastebin.* paste.ee ghostbin.com drive.google.com ?.docs.live.net api.dropboxapi.* content.dropboxapi.* *dl.dropboxusercontent.*
api.onedrive.com *.onedrive.org onedrive.live.com filebin.net *.ngrok.io ngrok.com *.portmap.* *serveo.net *localtunnel.me *pagekite.me
*localxpose.io *notabug.org rawcdn.githack.* paste.nrecom.net zerobin.net controlc.com requestbin.net api.slack.com slack-redir.net
slack-files.com cdn.discordapp.com discordapp.com discord.com apis.azureedge.net cdn.sql.gg ?.top4top.io top4top.io uplooder.net
*.cdnmegafiles.com transfer.sh updates.peer2profit.com api.telegram.org t.me meacz.gq rwrd.org *.publicvm.com *.blogspot.com
api.mylnikov.org script.google.com script.googleusercontent.com paste4btc.com workupload.com temp.sh filetransfer.io gofile.io
store?.gofile.io tiny.one api.notion.com *.sharepoint.com *upload.ee bit.ly t.ly cutt.ly mbasic.facebook.com api.gofile.io file.io
api.anonfiles.com api.trello.com gist.githubusercontent.com dpaste.com *azurewebsites.net *.zulipchat.com *.4shared.com filecloud.me
i.ibb.co files.catbox.moe *.getmyip.com mockbin.org webhook.site run.mocky.io *infinityfreeapp.com free.keep.sh tinyurl.com
ftpupload.net lobfile.com *.ngrok-free.app myexternalip.com yandex.ru *.yandex.ru *.aternos.me cdn??.space *.pcloud.com mediafire.zip
urlz.fr rentry.co *.b-cdn.net pastecode.dev i.imgur.com the.earth.li *.trycloudflare.com *.blob.core.windows.net
*.blob.storage.azure.net""".split()


def suspicious_service(evs):
    """Unusual Network Connection to Suspicious Web Service (new terms, medium)"""
    out = set()
    for k, _, d in evs:
        dom = d.get("destination", {}).get("domain") if k == "network" else None
        if not dom or not like(dom, *SERVICES):
            continue
        sig = d["process"]["code_signature"]
        if sig["trusted"] and sig["subject_name"] == "Software Signing":  # the rule's exceptions for Apple's own and for browsers
            continue
        out.add(f"{d['process']['name']} -> {dom}")
    return sorted(out)


ALL = [curl_from_npm, editor_credentials, python_shell_commands, vscode_command, vsix_install, recursive_grep, cloud_tokens,
       profile_modified, sudoers_echo, node_dns, python_shell_first, suspicious_tld, suspicious_service]

if __name__ == "__main__":
    out = {}
    for case in sorted(os.listdir(elastic.RECORDINGS)):
        for side in ("attack", "twin"):
            d = os.path.join(elastic.RECORDINGS, case, side)
            if os.path.isdir(d):
                evs = elastic.ecs(d)
                hits = {}
                for f in ALL:
                    got = f(evs)
                    if got:
                        name, kind = f.__doc__.rsplit(" (", 1)
                        hits[name] = {"kind": kind.rstrip(")"), "count": len(got), "first": str(got[0])[:300]}
                out[f"{case}/{side}"] = hits
    json.dump(out, sys.stdout, indent=1)
