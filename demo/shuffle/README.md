# Local Shuffle lab

A local [Shuffle](https://shuffler.io) SOAR for developing and demoing anysoar's Shuffle
driver. It runs Shuffle 2.3.0 natively on Apple Silicon or x86 with Docker.

```bash
./up.sh               # start; first run generates secrets into .env.local and pulls images
./down.sh             # stop, keeping data
./down.sh --purge     # remove containers, data, Shuffle's app images and .env.local
```

`up.sh` prints the web UI address (http://localhost:3001, user `admin`), the API address, and
the `SHUFFLE_URL` / `SHUFFLE_API_KEY` variables the driver uses. The admin password and API
key are random per install and live only in `.env.local`, which is git-ignored.

## Before you run it

- **It controls Docker on your machine.** Shuffle's backend and orborus mount the Docker
  socket, because Shuffle runs each workflow step in its own container. Use it as a local
  lab, not next to anything sensitive in Docker.
- **Resources:** about 3 GB of images, and 2–3 GB of memory while running (OpenSearch has a
  1 GB heap). Give Docker Desktop at least 4 GB.
- **Ports** are bound to 127.0.0.1 only: 3001 (web UI) and 5001 (API).
- **Shuffle logs its API key** in plain text (`docker compose logs backend`). Don't share those
  logs; `./down.sh --purge && ./up.sh` gives you new secrets.

## How this differs from Shuffle's own docker-compose.yml

- Versions are pinned, and ports are not exposed beyond localhost.
- The admin user and API key are created at startup, so no setup in the web UI is needed.
- **No Docker Swarm.** Upstream sets `SHUFFLE_SWARM_CONFIG=run`, which makes orborus put
  the whole Docker engine into Swarm mode and run workers as Swarm services. Here orborus
  runs workflow containers directly, which is enough for a lab.
- **No Tenzir.** Orborus otherwise starts a `tenzir-node` pipeline container from an
  unpinned image. `SHUFFLE_SKIP_PIPELINES=true` turns that off.
- The `shuffle-security` incidents UI is left out: its image is amd64-only and the API
  works without it.
- **No self-test loop.** Shuffle's built-in health check runs a many-step test workflow over
  and over, so containers appear and disappear constantly in Docker Desktop.
  `SHUFFLE_HEALTHCHECK_DISABLED=true` turns it off.

## Notes

- `GET /api/v1/health` runs Shuffle's operations health check and fails until an admin has
  run it once; use `GET /api/v1/_ah/health` to check that the API is up.
- **First start.** It takes about 30 seconds for the admin user and API key to exist, then
  Shuffle registers its default apps (including Shuffle Tools) and builds their images,
  which takes another minute or two of brief containers in Docker Desktop.
- **No apps loaded.** If `GET /api/v1/apps` still returns `[]` after a few minutes, `POST
  /api/v1/apps/download_remote` with
  `{"url": "https://github.com/shuffle/python-apps", "branch": "master"}` registers them,
  but it also builds a Docker image for every app (about 150, many GB). Restart the
  backend (`docker compose --env-file .env.local restart backend`) once the apps are
  registered to stop the builds; Shuffle pulls the images it needs when a workflow runs.
- Each workflow run starts a worker container and one container per step; that is normal.
