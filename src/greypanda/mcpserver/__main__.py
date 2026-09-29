"""Enable ``python -m greypanda.mcpserver``."""

from .server import serve_stdio

if __name__ == "__main__":
    serve_stdio()
