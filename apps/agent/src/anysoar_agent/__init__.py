"""anysoar-agent: a reference agent that operates a SOAR through anysoar's MCP server.

The loop (:class:`Agent`) is independent of the LLM provider: models implement
:class:`~anysoar_agent.model.Model`, and tools come from any MCP server via
:class:`McpToolbox`.
"""

from anysoar_agent.agent import Agent, AgentEvent, AgentResult
from anysoar_agent.toolbox import McpToolbox

__all__ = ["Agent", "AgentEvent", "AgentResult", "McpToolbox"]
