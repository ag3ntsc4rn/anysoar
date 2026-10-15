"""The anysoar MCP server. Needs the ``mcp`` extra: ``pip install "anysoar[mcp]"``.

:func:`create_server` exposes a :class:`~anysoar.policy.GuardedDriver`'s operations as MCP
tools. With an :class:`ElicitationApprover`, write actions are approved by the user in their
MCP client.
"""

from anysoar.mcp.server import ApprovalForm, ElicitationApprover, create_server

__all__ = ["ApprovalForm", "ElicitationApprover", "create_server"]
