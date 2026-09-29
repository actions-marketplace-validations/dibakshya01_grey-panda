"""Grey Panda as an MCP server — expose scanning + advice to any AI IDE."""

from .server import serve_stdio, TOOLS

__all__ = ["serve_stdio", "TOOLS"]
