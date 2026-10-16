"""The ``anysoar-mcp`` command: run the anysoar MCP server over stdio."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import importlib.util
import logging
import os
import sys
import tomllib
from collections.abc import Callable, Sequence
from pathlib import Path

from pydantic import ValidationError

from anysoar import __version__
from anysoar.drivers import SoarSwitch, SwitchableDriver
from anysoar.drivers.mock import MockDriver
from anysoar.interface import Driver
from anysoar.policy import (
    DEFAULT_TIER_DECISIONS,
    Approver,
    GuardedDriver,
    HttpApprover,
    JsonlAuditLog,
    KillSwitch,
    Policy,
)

__all__ = ["DRIVERS", "load_policy", "main", "state_dir"]

logger = logging.getLogger("anysoar.mcp")


def _shuffle() -> Driver:
    from anysoar.drivers.shuffle import ShuffleDriver

    return ShuffleDriver()  # configured by SHUFFLE_URL and SHUFFLE_API_KEY


def _tines() -> Driver:
    from anysoar.drivers.tines import TinesDriver

    return TinesDriver()  # configured by TINES_URL, TINES_API_KEY and TINES_TEAM_ID


DRIVERS: dict[str, Callable[[], Driver]] = {
    "mock": MockDriver,
    "shuffle": _shuffle,
    "tines": _tines,
}
"""Drivers the command can start, by name. Real SOARs are configured by environment
variables, e.g. ``SHUFFLE_URL`` and ``SHUFFLE_API_KEY``."""


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
        default=env("ANYSOAR_DRIVER", "mock"),
        help=f"SOAR driver to use: {', '.join(sorted(DRIVERS))} (env ANYSOAR_DRIVER; "
        "default: %(default)s). shuffle reads SHUFFLE_URL and SHUFFLE_API_KEY, tines "
        "TINES_URL, TINES_API_KEY and optionally TINES_TEAM_ID. Several, "
        "comma-separated, serve whichever the --soar-switch file names (the first by default)",
    )
    parser.add_argument(
        "--soar-switch",
        type=Path,
        default=env("ANYSOAR_SOAR_SWITCH") or state_dir() / "SOAR",
        help="with several drivers, the file naming the active one "
        "(env ANYSOAR_SOAR_SWITCH; default: %(default)s)",
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
    parser.add_argument(
        "--approver",
        choices=["client", "http"],
        default=env("ANYSOAR_APPROVER", "client"),
        help="who approves write actions: 'client' asks the user in their MCP client; "
        "'http' asks an approval service such as the anysoar console, at --approval-url "
        "with the token in ANYSOAR_APPROVAL_TOKEN (env ANYSOAR_APPROVER; default: %(default)s)",
    )
    parser.add_argument(
        "--approval-url",
        default=env("ANYSOAR_APPROVAL_URL"),
        help="approval service address for --approver http (env ANYSOAR_APPROVAL_URL)",
    )
    parser.add_argument(
        "--approval-timeout",
        type=float,
        default=float(env("ANYSOAR_APPROVAL_TIMEOUT", "300")),
        help="seconds to wait for a decision before denying (default: %(default)g)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _driver(args: argparse.Namespace) -> Driver:
    names = [n.strip() for n in args.driver.split(",") if n.strip()]
    unknown = [n for n in names if n not in DRIVERS]
    if not names or unknown or len(set(names)) != len(names):
        sys.exit(
            f"anysoar-mcp: --driver must name distinct drivers from: {', '.join(sorted(DRIVERS))}"
        )
    drivers: dict[str, Driver] = {}
    for name in names:
        try:
            drivers[name] = DRIVERS[name]()
        except ValueError as exc:
            sys.exit(f"anysoar-mcp: cannot start the {name} driver: {exc}")
    if len(drivers) == 1:
        return drivers[names[0]]
    switch = SoarSwitch(args.soar_switch, names, default=names[0])
    logger.info("serving %s; the active SOAR is named in %s", ", ".join(names), args.soar_switch)
    return SwitchableDriver(drivers, switch)


def _approver(args: argparse.Namespace) -> Approver:
    if args.approver == "client":
        from anysoar.mcp.server import ElicitationApprover

        return ElicitationApprover()
    token = os.environ.get("ANYSOAR_APPROVAL_TOKEN")
    if not args.approval_url or not token:
        sys.exit("anysoar-mcp: --approver http needs --approval-url and ANYSOAR_APPROVAL_TOKEN")
    return HttpApprover(args.approval_url, token)


async def _serve(
    args: argparse.Namespace, policy: Policy, driver: Driver, approver: Approver
) -> None:
    from anysoar.mcp.server import create_server

    guard = GuardedDriver(
        driver,
        policy=policy,
        approver=approver,
        approval_timeout=args.approval_timeout,
        audit_log=JsonlAuditLog(args.audit_log),
        kill_switch=KillSwitch(args.kill_switch),
    )
    async with guard:
        server = await create_server(guard)
        logger.info(
            "serving driver %r; approvals by %s; audit log %s; kill switch file %s",
            args.driver,
            args.approval_url if args.approver == "http" else "the MCP client",
            args.audit_log,
            args.kill_switch,
        )
        await server.run_stdio_async()


def main(argv: Sequence[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    if importlib.util.find_spec("mcp") is None:
        sys.exit('anysoar-mcp needs the "mcp" extra: pip install "anysoar[mcp]"')
    # stdout carries the MCP protocol, so everything else goes to stderr.
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr, format="%(name)s: %(message)s")
    logging.getLogger("anysoar").setLevel(logging.INFO)  # the SDK's request logs stay quiet
    try:
        policy = load_policy(args.policy) if args.policy else Policy()
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        detail = str(exc) if not isinstance(exc, ValidationError) else f"\n{exc}"
        sys.exit(f"anysoar-mcp: invalid policy {args.policy}: {detail}")
    approver = _approver(args)
    driver = _driver(args)
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(_serve(args, policy, driver, approver))
