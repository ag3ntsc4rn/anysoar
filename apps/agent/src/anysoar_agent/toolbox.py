"""The agent's tools: whatever an MCP server offers, seen through the model interface."""

from __future__ import annotations

import json
from typing import Any

from mcp import Client
from mcp.types import CallToolResult

from anysoar_agent.model import ToolCall, ToolResult, ToolSpec

__all__ = ["McpToolbox"]


class McpToolbox:
    """Lists and calls the tools of a connected MCP client.

    The agent knows nothing about anysoar here: any MCP server works, which is the point of
    exposing a SOAR over MCP.
    """

    def __init__(self, client: Client) -> None:
        self.client = client

    async def tools(self) -> list[ToolSpec]:
        listed = await self.client.list_tools()
        return [
            ToolSpec(name=t.name, description=t.description or "", input_schema=t.input_schema)
            for t in listed.tools
        ]

    async def call(self, call: ToolCall) -> ToolResult:
        result = await self.client.call_tool(call.name, call.arguments)
        return ToolResult(call_id=call.id, content=_render(result), is_error=result.is_error)


def _render(result: CallToolResult) -> str:
    """Tool output as text for the model: structured content as compact JSON when present."""
    structured: Any = result.structured_content
    if structured is not None and not result.is_error:
        return json.dumps(structured, separators=(",", ":"), sort_keys=True)
    texts = [block.text for block in result.content if block.type == "text"]
    return "\n".join(texts) or ("tool failed" if result.is_error else "")
