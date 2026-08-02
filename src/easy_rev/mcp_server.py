"""MCP server exposing easy-rev AI tools.

Requires: pip install 'easy-rev[mcp]'

Run:
  python -m easy_rev.mcp_server
  # or
  easy-rev mcp
"""

from __future__ import annotations

import asyncio
import json
from typing import Any


def _tools_for_mcp() -> list[dict[str, Any]]:
    from easy_rev.ai.tools import TOOL_SPECS

    return [
        {
            "name": t["name"],
            "description": t.get("description") or t["name"],
            "inputSchema": t.get("input_schema") or {"type": "object", "properties": {}},
        }
        for t in TOOL_SPECS
    ]


async def _call(name: str, arguments: dict[str, Any] | None) -> dict[str, Any]:
    from easy_rev.ai.handlers import call_tool

    return await call_tool(name, arguments or {})


def main() -> None:
    """Start stdio MCP server; fail clearly if mcp package missing."""
    try:
        from mcp.server import Server
        from mcp.server.stdio import stdio_server
        from mcp.types import TextContent, Tool
    except Exception as e:  # noqa: BLE001
        raise SystemExit(
            "MCP SDK not installed. Run: pip install 'easy-rev[mcp]'\n"
            f"Import error: {e}"
        ) from e

    server = Server("easy-rev")

    @server.list_tools()
    async def list_tools() -> list[Tool]:  # type: ignore[misc]
        tools = []
        for t in _tools_for_mcp():
            tools.append(
                Tool(
                    name=t["name"],
                    description=t["description"],
                    inputSchema=t["inputSchema"],
                )
            )
        return tools

    @server.call_tool()
    async def call_tool_handler(name: str, arguments: dict[str, Any] | None):  # type: ignore[misc]
        result = await _call(name, arguments or {})
        text = json.dumps(result, ensure_ascii=False, indent=2, default=str)
        return [TextContent(type="text", text=text)]

    async def _run() -> None:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())

    asyncio.run(_run())


if __name__ == "__main__":
    main()
