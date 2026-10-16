"""The ``anysoar-console`` command: run the console on localhost."""

from __future__ import annotations

import argparse
import os
import socket
import sys
from collections.abc import Sequence
from pathlib import Path

import uvicorn

from anysoar.mcp.cli import state_dir
from anysoar_console.app import ConsoleConfig, create_app

__all__ = ["connection_file", "main"]

HOST = "127.0.0.1"


def connection_file() -> Path:
    """Where the console writes the address and submit token anysoar needs."""
    return state_dir() / "console.env"


def write_connection_file(path: Path, url: str, submit_token: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as file:
        file.write(
            "# Written by anysoar-console. Lets anysoar ask this console for approvals.\n"
            f"ANYSOAR_APPROVAL_URL={url}\nANYSOAR_APPROVAL_TOKEN={submit_token}\n"
        )


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="anysoar-console",
        description="Local web console: approve or reject actions agents take through "
        "anysoar, and watch them work. Listens on 127.0.0.1 only.",
    )
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument(
        "--operator",
        default=os.environ.get("ANYSOAR_OPERATOR", "console"),
        help="name recorded as the approver of your decisions (default: %(default)s)",
    )
    args = parser.parse_args(argv)

    with socket.socket() as probe:
        if probe.connect_ex((HOST, args.port)) == 0:
            sys.exit(f"anysoar-console: port {args.port} is in use; pick another with --port")

    config = ConsoleConfig(operator=args.operator)
    url = f"http://{HOST}:{args.port}"
    connection = connection_file()
    write_connection_file(connection, url, config.submit_token)
    print(
        f"anysoar console on {url}\n\n"
        f"  Sign in:  {url}/login?token={config.login_token}\n"
        "            (only this link signs in; it is not saved anywhere)\n\n"
        f"  anysoar-mcp --approver http reads its settings from {connection}\n",
        flush=True,
    )

    def forget() -> None:
        connection.unlink(missing_ok=True)

    # uvicorn re-raises SIGTERM after shutting down, so cleanup runs in the app's shutdown.
    app = create_app(config, on_shutdown=forget)
    try:
        uvicorn.run(app, host=HOST, port=args.port, log_level="warning")
    finally:
        forget()
