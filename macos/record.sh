#!/bin/bash
# record.sh CASE attack|twin [OUT_DIR]: one recording. A fresh copy of the
# developer VM is started, the pack's sensor and network capture are started
# in it, the case's lines are typed into its Terminal window, and after the
# case's settle time the capture is stopped and brought back:
#
#   OUT_DIR/es.ndjson.zst    a process snapshot, then the sensor's lines (the recorder's own taken out: scrub.py)
#   OUT_DIR/net.ndjson       net.py's lines
#   OUT_DIR/prompts.ndjson   transcripts.py's lines: what the person typed to a coding agent
#   OUT_DIR/published.ndjson what the VM published to the stand-in registry
#   OUT_DIR/received.ndjson  what was sent to the case's `hosts`: method, host, path and size, no content
#
# The VM copy is deleted afterwards. Needs: tart, the VM `evaldev`
# (README.md), TANGENT_ROOT at a tangent checkout with packs/macos, and a
# notarized sensor (a release's, or packs/macos/sensor/README.md's Developer
# ID build) at SENSOR_APP, by default TangentSensor.app in the state
# directory. A development build runs only on the Macs in its profile, and a
# VM is never one of them.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
case=${1:?usage: record.sh CASE attack|twin [OUT_DIR]}
what=${2:?usage: record.sh CASE attack|twin [OUT_DIR]}
out=${3:-$here/../runs/macos/recordings/$case/$what}
pack=${TANGENT_ROOT:?set TANGENT_ROOT to a tangent checkout}/packs/macos
state=${TANGENT_EVAL_STATE:-$HOME/.local/share/tangent-eval}
sensor=${SENSOR_APP:-$state/sensor/TangentSensor.app}
dir=$here/cases/$case
[ -f "$dir/$what.sh" ] || { echo "no $dir/$what.sh" >&2; exit 1; }
[ -d "$sensor" ] || { echo "no sensor at $sensor" >&2; exit 1; }
signed=$(codesign -dv --verbose=2 "$sensor" 2>&1 || true)
[[ $signed == *"Authority=Developer ID Application"* ]] \
  || { echo "$sensor is not a Developer ID build: it will not start in a VM" >&2; exit 1; }
settle=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["settle"])' "$dir/case.json")
vm=rec-$case-$what
mkdir -p "$out"

# the stand-in, for as long as the VM runs: the registry with this case's
# packages, PyPI with its `pypi` projects, and the case's `hosts` (the
# attacker's servers), which take whatever is sent and keep none of it
field() { python3 -I -c 'import json,sys; [print(v) for v in json.load(open(sys.argv[1])).get(sys.argv[2], [])]' "$dir/case.json" "$1"; }
dirs=$(field registry | sed "s|^|$dir/|")
hosts=$(field hosts)
pypi=$(field pypi | sed "s|^|--pypi $dir/|")
serve=$(python3 -I -c 'import json,sys; [print(f"--serve {k}={sys.argv[2]}/{v}") for k, v in json.load(open(sys.argv[1])).get("serve", {}).items()]' "$dir/case.json" "$dir")
repos=$(python3 -I -c 'import json,sys; [print(f"--repo {k}={sys.argv[2]}/{v}") for k, v in json.load(open(sys.argv[1])).get("repos", {}).items()]' "$dir/case.json" "$dir")
# every name that is the stand-in in this VM: the case's hosts, and for a
# case with PyPI projects the two names pip talks to
names=$hosts
[ -z "$pypi" ] || names="$hosts pypi.org files.pythonhosted.org"
# a case with `agent` runs Claude Code in the VM: its requests to
# api.anthropic.com come to the stand-in, which passes them to MODEL_API
# (default OpenRouter's Messages API) with MODEL_API_KEY. The names in `agent`
# are answered the same way: where a hijacked agent's traffic is sent.
model=
if python3 -I -c 'import json,sys; sys.exit("agent" not in json.load(open(sys.argv[1])))' "$dir/case.json"; then
  [ -n "${MODEL_API_KEY:-}" ] || { echo "$case runs a coding agent: set MODEL_API_KEY" >&2; exit 1; }
  model="--model-api ${MODEL_API:-https://openrouter.ai/api} $(field agent | sed 's/^/--model-name /' | tr '\n' ' ')"
  names="$names api.anthropic.com $(field agent | tr '\n' ' ')"
fi
tls=$(mktemp -d)
# shellcheck disable=SC2086
"$here/standin/certs.sh" "$state/certs" "$tls" $names
: > "$out/published.ndjson"
: > "$out/received.ndjson"
# shellcheck disable=SC2086
python3 -I "$here/standin/registry.py" --cert "$tls/leaf.pem" --key "$tls/leaf.key" \
  --log "$out/published.ndjson" --sink-log "$out/received.ndjson" $(field http_ports | sed 's/^/--http-port /') $model $serve $repos $pypi $dirs 2> "$out/registry.log" &
registry=$!
sleep 1
kill -0 "$registry" 2>/dev/null || { echo "the stand-in did not start: $(tail -1 "$out/registry.log")" >&2; exit 1; }

tart clone evaldev "$vm"
tart run --no-graphics "$vm" > /dev/null 2>&1 &
finish() {
  kill "$registry" 2>/dev/null || true
  rm -rf "$tls"
  tart stop "$vm" 2>/dev/null || true
  tart delete "$vm" 2>/dev/null || true
}
trap finish EXIT
for _ in $(seq 90); do tart exec "$vm" true 2>/dev/null && break; sleep 2; done
sleep 30   # the login's own start-up, out of the recording
vssh=(ssh -i "$state/vm_key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "admin@$(tart ip "$vm")")

# the case's hosts (and PyPI, for a case that has it) are the stand-in, in this VM
[ -z "$names" ] || "${vssh[@]}" "for h in $(echo $names); do echo \"192.168.64.1 \$h\" | sudo tee -a /etc/hosts > /dev/null; done"
# pip keeps its own list of authorities and does not read the keychain. It is
# told of the stand-in's in its machine-wide config file, written now, before
# the capture: a variable or an option on the typed line would be in the
# recording, and a file in the home would be in a payload's sweep of it.
[ -z "$pypi" ] || "${vssh[@]}" "sudo mkdir -p '/Library/Application Support/pip' && printf '[global]\ncert = /etc/tangent-eval-ca.pem\n' | sudo tee '/Library/Application Support/pip/pip.conf' > /dev/null"

# Outside the home directory: a case that scans the home must not find the capture.
rec=/private/var/tmp/rec
tar -C "$pack" -cf - ps/ps.py net/net.py agent/transcripts.py -C "$(dirname "$sensor")" TangentSensor.app -C "$here/vm" capture.sh -C "$dir" "$what.sh" \
  | "${vssh[@]}" "mkdir -p $rec && tar -C $rec -xf -"

# One ssh session for the whole capture: it is there before the sensor starts
# and nothing else is sent to the VM until the sensor has stopped.
"${vssh[@]}" "$rec/capture.sh $rec/$what.sh $settle" < /dev/null | tee "$out/capture.log"
[ "${PIPESTATUS[0]}" = 0 ] || { echo "the capture failed: $out/capture.log" >&2; exit 1; }
"${vssh[@]}" "cd $rec && cat ps1.ndjson monitor.ndjson ps2.ndjson es.ndjson" > "$out/es.raw.ndjson"
"${vssh[@]}" "cat $rec/net.ndjson" > "$out/net.raw.ndjson"
"${vssh[@]}" "cat $rec/prompts.ndjson" > "$out/prompts.ndjson"   # what the person typed to a coding agent, as the pack is told it
python3 -I "$here/scrub.py" "$out/es.raw.ndjson" "$out/net.raw.ndjson" "$out"   # the recorder itself, out of the recording
rm "$out/es.raw.ndjson" "$out/net.raw.ndjson"
echo "$out: $(zstd -dc "$out/es.ndjson.zst" | wc -l | tr -d ' ') sensor lines, $(wc -l < "$out/net.ndjson" | tr -d ' ') connections, $(wc -l < "$out/published.ndjson" | tr -d ' ') published, $(wc -l < "$out/received.ndjson" | tr -d ' ') requests to the case's hosts"
