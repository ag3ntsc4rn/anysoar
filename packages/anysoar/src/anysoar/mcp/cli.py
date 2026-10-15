"""The ``anysoar-mcp`` command: run the anysoar MCP server over stdio."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import os
import sys
import tomllib
from collections.abc import Callable, Sequence
from pathlib import Path

from pydantic import ValidationError

from anysoar import __version__
from anysoar.drivers.mock import MockDriver
from anysoar.interface import Driver
from anysoar.policy import (
    DEFAULT_TIER_DECISIONS,
    GuardedDriver,
    JsonlAuditLog,
    KillSwitch,
    Policy,
)

__all__ = ["DRIVERS", "load_policy", "main", "state_dir"]

logger = logging.getLogger("anysoar.mcp")

DRIVERS: dict[str, Callable[[], Driver]] = {"mock": MockDriver}
"""Drivers the command can start, by name."""


def state_dir() -> Path:
    """Where anysoar keeps its audit log and kill switch file by default.

    ``$XDG_STATE_HOME/anysoar``, or ``~/.local/state/anysoar`` if that is not set.
    """
    base = os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state"
    return Path(base) / "anysoar"


def load_policy(path: Path) -> Policy:
    """Load a policy from TOML. Tiers not listed keep their defaults.

    Example::

        [tiers]
        write = "require_approval"

        [capabilities]
        add_note = "allow"

        [playbooks]
        pb-notify-reporter = "allow"
    """
    with path.open("rb") as file:
        data = tomllib.load(file)
    unknown = set(data) - {"tiers", "capabilities", "playbooks"}
    if unknown:
        raise ValueError(f"unknown policy sections: {', '.join(sorted(unknown))}")
    tiers = {tier.value: decision.value for tier, decision in DEFAULT_TIER_DECISIONS.items()}
    tiers.update(data.get("tiers", {}))
    return Policy.model_validate({**data, "tiers": tiers})


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="anysoar-mcp",
        description="Run the anysoar MCP server over stdio. Reads run freely, writes need "
        "the user's approval in the MCP client, destructive actions are denied.",
    )
    env = os.environ.get
    parser.add_argument(
        "--driver",
        choices=sorted(DRIVERS),
        default=env("ANYSOAR_DRIVER", "mock"),
        help="SOAR driver to use (env ANYSOAR_DRIVER; default: %(default)s)",
    )
    parser.add_argument(
        "--policy",
        type=Path,
        default=env("ANYSOAR_POLICY"),
        help="policy TOML file (env ANYSOAR_POLICY; default: built-in policy)",
    )
    parser.add_argument(
        "--audit-log",
        type=Path,
        default=env("ANYSOAR_AUDIT_LOG") or state_dir() / "audit.jsonl",
        help="JSONL audit log to append to (env ANYSOAR_AUDIT_LOG; default: %(default)s)",
    )
    parser.add_argument(
        "--kill-switch",
        type=Path,
        default=env("ANYSOAR_KILL_SWITCH") or state_dir() / "STOP",
        help="while this file exists, every operation is denied "
        "(env ANYSOAR_KILL_SWITCH; default: %(default)s)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


async def _serve(args: argparse.Namespace, policy: Policy) -> None:
    from anysoar.mcp.server import ElicitationApprover, create_server

    guard = GuardedDriver(
        DRIVERS[args.driver](),
        policy=policy,
        approver=ElicitationApprover(),
        audit_log=JsonlAuditLog(args.audit_log),
        kill_switch=KillSwitch(args.kill_switch),
    )
    async with guard:
        server = await create_server(guard)
        logger.info(
            "serving driver %r; audit log %s; kill switch file %s",
            args.driver,
            args.audit_log,
            args.kill_switch,
        )
        await server.run_stdio_async()


def main(argv: Sequence[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    # stdout carries the MCP protocol, so everything else goes to stderr.
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(name)s: %(message)s")
    try:
        policy = load_policy(args.policy) if args.policy else Policy()
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        detail = str(exc) if not isinstance(exc, ValidationError) else f"\n{exc}"
        sys.exit(f"anysoar-mcp: invalid policy {args.policy}: {detail}")
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(_serve(args, policy))
