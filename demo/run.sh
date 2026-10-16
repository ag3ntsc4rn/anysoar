#!/usr/bin/env bash
# The anysoar demo: an AI agent triages phishing cases on one SOAR, you approve its actions
# in the console, then you switch the SOAR to Shuffle and the same running agent carries on.
#
#   demo/run.sh            # offline: a scripted agent, no API key needed
#   demo/run.sh --claude   # Claude does the triage (needs ANTHROPIC_API_KEY)
#
# Any other arguments are passed to `anysoar-agent watch`, e.g. --max-cases 4.
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo"

provider=(--provider demo)
if [[ ${1:-} == --claude ]]; then
  provider=(--provider claude)
  shift
  [[ -n ${ANTHROPIC_API_KEY:-} ]] || { echo "--claude needs ANTHROPIC_API_KEY" >&2; exit 1; }
fi

state="${XDG_STATE_HOME:-$HOME/.local/state}/anysoar"
mkdir -p "$state"

echo "== Starting the local Shuffle lab (first run takes a few minutes)"
demo/shuffle/up.sh --ui 2>&1 | grep -E "Shuffle is running|Incidents UI|Web UI|not loaded|rejected|did not" || true
uv run demo/shuffle/seed.py >/dev/null
echo "   Loaded the phishing scenario into Shuffle"

export SHUFFLE_URL=http://127.0.0.1:5001
SHUFFLE_API_KEY="$(grep ^SHUFFLE_API_KEY= demo/shuffle/.env.local | cut -d= -f2)"
export SHUFFLE_API_KEY

echo mock >"$state/SOAR"
if [[ -e $state/STOP ]]; then
  echo "!! The kill switch is engaged ($state/STOP): every action will be denied."
  echo "   Resume it in the console, or delete that file."
fi

echo "== Starting the console"
console_log="$state/console.log"
uv run anysoar-console --soars mock,shuffle --operator "${USER:-analyst}" >"$console_log" 2>&1 &
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
   Shuffle's own UI:  http://localhost:3002  (incidents; user admin, password in demo/shuffle/.env.local)

   1. Approve or reject the agent's actions in the console as they appear.
   2. After a case or two, when the agent panel shows "Finished", click "shuffle" next to
      SOAR in the console header. The same agent keeps running; its next case comes from
      Shuffle.
   3. Try "Stop all actions", then Resume.

EOF
if [[ -z ${DEMO_NO_WAIT:-} ]]; then
  read -r -p "Press Enter once the console is open in your browser… "
fi

echo "== Starting the agent (Ctrl-C to stop)"
uv run anysoar-agent watch "${provider[@]}" --console --interval 3 \
  --server-arg=--driver=mock,shuffle "$@"
