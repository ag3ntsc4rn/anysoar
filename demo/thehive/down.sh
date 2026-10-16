#!/usr/bin/env bash
# Stop the local TheHive + Cortex lab. With --purge, also delete its data, analyzer job files
# and generated secrets; the next ./up.sh then starts fresh, with a new trial license.
set -euo pipefail
cd "$(dirname "$0")"

env_file=.env.local
# Compose checks these are set even when stopping; .env.local is not needed for that.
export CORTEX_JOB_DIR=$PWD/.cortex-jobs THEHIVE_SECRET=unused

if [[ ${1:-} == --purge ]]; then
  docker compose down --volumes --remove-orphans
  rm -rf .cortex-jobs "$env_file"
  echo "TheHive lab removed, including its data and $env_file."
else
  docker compose down --remove-orphans
  echo "TheHive lab stopped. Data is kept; ./up.sh starts it again."
fi
