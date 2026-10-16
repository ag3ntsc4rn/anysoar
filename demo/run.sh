#!/usr/bin/env bash
# The anysoar demo: an AI agent triages phishing cases on one SOAR, you approve its actions
# in the console, then you switch the SOAR to a real one and the same running agent carries on.
#
#   demo/run.sh                  # switch to TheHive with Cortex; a scripted agent, no API key
#   demo/run.sh --claude         # Claude does the triage (needs ANTHROPIC_API_KEY)
#   demo/run.sh --soar shuffle   # switch to Shuffle instead (lighter; no alerts or enrichment)
#
# Any other arguments are passed to `anysoar-agent watch`, e.g. --max-cases 4.
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo"

provider=(--provider demo)
soar=thehive
while [[ $# -gt 0 ]]; do
  case $1 in
    --claude)
      provider=(--provider claude)
      [[ -n ${ANTHROPIC_API_KEY:-} ]] || { echo "--claude needs ANTHROPIC_API_KEY" >&2; exit 1; }
      shift
      ;;
    --soar)
      soar=${2:-}
      shift 2 || true
      ;;
    --soar=*)
      soar=${1#--soar=}
      shift
      ;;
    *) break ;;
  esac
done
[[ $soar == shuffle || $soar == thehive ]] || { echo "--soar takes shuffle or thehive" >&2; exit 1; }

state="${XDG_STATE_HOME:-$HOME/.local/state}/anysoar"
mkdir -p "$state"

if [[ $soar == shuffle ]]; then
  echo "== Starting the local Shuffle lab (first run takes a few minutes)"
  demo/shuffle/up.sh --ui 2>&1 | grep -E "Shuffle is running|Incidents UI|Web UI|not loaded|rejected|did not" || true
  uv run demo/shuffle/seed.py >/dev/null
  echo "   Loaded the phishing scenario into Shuffle"
  export SHUFFLE_URL=http://127.0.0.1:5001
  SHUFFLE_API_KEY="$(grep ^SHUFFLE_API_KEY= demo/shuffle/.env.local | cut -d= -f2)"
  export SHUFFLE_API_KEY
  soar_ui="Shuffle's own UI:  http://localhost:3002  (incidents; user admin, password in demo/shuffle/.env.local)"
  soar_note="It has fewer tools there: Shuffle has no alerts or indicator enrichment."
else
  echo "== Starting the local TheHive lab with Cortex (first run takes a few minutes)"
  demo/thehive/up.sh 2>&1 | grep -E "are running|License|up.sh:|did not" || true
  uv run demo/thehive/seed.py >/dev/null
  echo "   Loaded the phishing scenario into TheHive"
  export THEHIVE_URL=http://127.0.0.1:9000
  THEHIVE_API_KEY="$(grep ^THEHIVE_API_KEY= demo/thehive/.env.local | cut -d= -f2)"
  export THEHIVE_API_KEY
  soar_ui="TheHive's own UI:  http://localhost:9000  (user analyst@anysoar.lab, password in demo/thehive/.env.local)"
  soar_note="There it looks indicators up with Cortex analyzers, about 10 seconds each."
fi

echo mock >"$state/SOAR"
if [[ -e $state/STOP ]]; then
  echo "!! The kill switch is engaged ($state/STOP): every action will be denied."
  echo "   Resume it in the console, or delete that file."
fi

echo "== Starting the console"
console_log="$state/console.log"
uv run anysoar-console --soars "mock,$soar" --operator "${USER:-analyst}" >"$console_log" 2>&1 &
console_pid=$!
trap 'kill "$console_pid" 2>/dev/null || true' EXIT
for _ in $(seq 1 100); do
  grep -q "Sign in" "$console_log" 2>/dev/null && break
  kill -0 "$console_pid" 2>/dev/null || { cat "$console_log" >&2; exit 1; }
  sleep 0.2
done
sign_in="$(grep -o 'http://127.0.0.1:[0-9]*/login?token=[^ ]*' "$console_log")"

cat <<EOF

   Open the console:  $sign_in
   $soar_ui

   1. Approve or reject the agent's actions in the console as they appear.
   2. After a case or two, when the status above the Agent feed turns green ("Finished
      ... A good moment to switch the SOAR"), click "$soar" next to SOAR in the console
      header. The same agent keeps running; its next case comes from $soar. $soar_note
   3. Try "Stop all actions", then Resume.

EOF
if [[ -z ${DEMO_NO_WAIT:-} ]]; then
  read -r -p "Press Enter once the console is open in your browser… "
fi

echo "== Starting the agent (Ctrl-C to stop)"
uv run anysoar-agent watch "${provider[@]}" --console --interval 3 \
  --server-arg=--driver="mock,$soar" "$@"
