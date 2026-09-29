"""Grey Panda as an MCP server — expose scanning + advice to any AI IDE."""

from .server import TOOLS, serve_stdio

__all__ = ["serve_stdio", "TOOLS"]
