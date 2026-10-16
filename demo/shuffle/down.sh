#!/usr/bin/env bash
# Stop the local Shuffle lab. With --purge, also delete its data and generated secrets.
set -euo pipefail
cd "$(dirname "$0")"

env_file=.env.local
args=(--env-file "$env_file" --profile ui)  # the profile so the optional UI stops too
[[ -f $env_file ]] || args=(--profile ui)

if [[ ${1:-} == --purge ]]; then
  docker compose "${args[@]}" down --volumes --remove-orphans
  # Containers orborus started for workflow runs are not part of the compose project.
  for image in frikky/shuffle "ghcr.io/shuffle/shuffle-worker:${SHUFFLE_VERSION:-2.3.0}"; do
    docker ps -aq --filter "ancestor=$image" | xargs -r docker rm -f >/dev/null
  done
  # App images Shuffle pulled or built for itself.
  docker images -q frikky/shuffle | xargs -r docker rmi -f >/dev/null
  rm -f "$env_file"
  echo "Shuffle lab removed, including its data, app images and $env_file."
else
  docker ps -q --filter ancestor=frikky/shuffle | xargs -r docker stop >/dev/null
  docker compose "${args[@]}" down --remove-orphans
  echo "Shuffle lab stopped. Data is kept; ./up.sh starts it again."
fi
