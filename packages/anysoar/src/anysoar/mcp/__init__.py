"""The anysoar MCP server. Needs the ``mcp`` extra: ``pip install "anysoar[mcp]"``.

:func:`create_server` exposes a :class:`~anysoar.policy.GuardedDriver`'s operations as MCP
tools. With an :class:`ElicitationApprover`, write actions are approved by the user in their
MCP client.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from anysoar.mcp.server import ApprovalForm, ElicitationApprover, create_server

__all__ = ["ApprovalForm", "ElicitationApprover", "create_server"]


def __getattr__(name: str) -> Any:
    # Imported on first use, so `anysoar-mcp --help` works without the mcp extra.
    if name in __all__:
        from anysoar.mcp import server

        return getattr(server, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
