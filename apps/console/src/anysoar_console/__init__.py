"""anysoar-console: a local web console for people supervising agents that use anysoar.

People approve or reject the actions agents ask to take; anysoar asks through
:class:`anysoar.policy.HttpApprover` (``anysoar-mcp --approver http``).
"""

from anysoar_console.app import ConsoleConfig, create_app

__all__ = ["ConsoleConfig", "create_app"]
