#!/usr/bin/env python3
"""
MCP Agent Host - Web UI Server Launcher
---------------------------------------
Starts the FastAPI backend and serves the interactive Web Dashboard.

Usage:
  python ui.py
  python ui.py --host 0.0.0.0 --port 8080
"""

import sys
import argparse
import uvicorn


def main():
    parser = argparse.ArgumentParser(description="MCP Agent Host Web UI Dashboard")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host interface (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind (default: 8000)")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload on code change")

    args = parser.parse_args()

    print(f"\n" + "=" * 65)
    print(f"  🛡️  MCP AGENT HOST INTERACTIVE MISSION CONTROL")
    print(f"=" * 65)
    print(f"  Dashboard URL : http://{args.host}:{args.port}")
    print(f"  API Docs (OAS): http://{args.host}:{args.port}/docs")
    print(f"=" * 65 + "\n")

    uvicorn.run("ui.app:app", host=args.host, port=args.port, reload=args.reload)


if __name__ == "__main__":
    main()
