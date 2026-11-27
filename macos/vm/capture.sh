#!/bin/bash
# capture.sh LINES SETTLE: runs inside the VM, over ssh, for one recording.
# It starts the capture as examples/macos/run.sh does, types each line of
# LINES into the Terminal window as a person would (real keystrokes, the next
# line once the shell is idle again), waits SETTLE seconds for what was left
# running, and stops the capture. Everything it does itself is its own
# process's or a child's, which the pack leaves out by the `monitor` line.
set -euo pipefail
lines=$1
settle=$2
cd "$(dirname "$0")"
sensor=TangentSensor.app/Contents/MacOS/tangent-sensor

python3 ps/ps.py > ps1.ndjson
echo "{\"time\":\"$(date -u +%Y-%m-%dT%H:%M:%S.000000000Z)\",\"monitor\":{\"pid\":$$}}" > monitor.ndjson
sudo "$sensor" > es.ndjson 2> es.err &
sleep 1
python3 ps/ps.py > ps2.ndjson
sudo tcpdump -i pktap,all -k NP -n -l -tt -X "$(python3 net/net.py --filter)" 2>/dev/null | python3 net/net.py > net.ndjson &
python3 agent/transcripts.py > prompts.ndjson &
prompts=$!
sleep 4
[ -s es.ndjson ] || { sudo pkill -x tcpdump || true; echo "the sensor wrote nothing (a development build is killed at launch in a VM): $(cat es.err)" >&2; exit 1; }

open -a Terminal
sleep 3
shell=$(pgrep -n -x -- -zsh)   # the window's login shell
typed=()
while IFS= read -r line; do
  case $line in ''|'#'*) continue ;; esac
  typed+=("$line")
done < "$lines"
for i in "${!typed[@]}"; do
  line=${typed[$i]}
  next=${typed[$((i + 1))]:-}
  # `>> text`: an answer to something the line before left on screen (a
  # dialog, a prompt), typed a few seconds on to whatever has the keyboard
  case $line in '>> '*) line=${line#>> }; sleep 5 ;; esac
  printf '%s' "$line" > line.txt
  osascript -e 'set t to (read POSIX file "'"$PWD"'/line.txt")' \
            -e 'tell application "System Events" to keystroke t' \
            -e 'tell application "System Events" to key code 36'
  sleep 2
  # a line that is about to be answered is still running: not waited for
  case $next in '>> '*) continue ;; esac
  # idle: the terminal's foreground group is the shell's own again (a job
  # the line left in the background does not hold the next line up)
  while [ "$(ps -o tpgid= -p "$shell" | tr -d ' ')" != "$(ps -o pgid= -p "$shell" | tr -d ' ')" ]; do sleep 1; done
  sleep 2
done
sleep "$settle"

sudo pkill -x tangent-sensor || true
sudo pkill -x tcpdump || true
kill "$prompts" 2>/dev/null || true
sleep 2
echo "typed ${#typed[@]} lines; $(wc -l < es.ndjson | tr -d ' ') sensor lines, $(wc -l < net.ndjson | tr -d ' ') connections"
