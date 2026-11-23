#!/usr/bin/env python3
"""
MCP Agent Host - Main CLI Entry Point
-------------------------------------
Launch the modular MCP agent host with dynamic model switching,
plug-and-play MCP server registration, scope guardrails, evidence persistence,
and grounded report generation.
"""

import sys
import argparse
import asyncio
from rich.console import Console

from core.agent import AgentHost


async def main_async(args: argparse.Namespace) -> None:
    console = Console()
    agent = AgentHost(
        config_dir=args.config_dir,
        active_model=args.model,
        auto_approve=args.auto_approve,
        session_id=args.session_id
    )

    try:
        # Initialize MCP Manager (connects enabled MCP servers)
        await agent.initialize()

        if args.demo:
            console.print("[bold cyan]🚀 Running Automated MCP Agent Host Demonstration...[/bold cyan]\n")
            demo_query = (
                "Perform a defensive assessment of http://example.com by checking its security headers, "
                "and inspect the audit log at sample_data/audit_sample.log for security anomalies."
            )
            console.print(f"[bold white]Query:[/bold white] {demo_query}\n")
            res = await agent.run_turn(demo_query)
            console.print(f"\n[bold green]Agent Synthesis Completed.[/bold green]\n")

            # Compile report
            reports = agent.reporter.compile_reports(agent.session_id)
            console.print(f"[bold green]✔ Assessment Reports Compiled:[/bold green]")
            console.print(f"  - Markdown: {reports['markdown']}")
            console.print(f"  - HTML:     {reports['html']}\n")

        elif args.query:
            console.print(f"[dim]Running query: {args.query}[/dim]")
            res = await agent.run_turn(args.query)
            console.print(f"\n[bold purple]Agent Response:[/bold purple]\n{res}\n")

            if args.report:
                reports = agent.reporter.compile_reports(agent.session_id)
                console.print(f"[bold green]✔ Reports Compiled:[/bold green]")
                console.print(f"  - Markdown: {reports['markdown']}")
                console.print(f"  - HTML:     {reports['html']}")

        else:
            # Interactive REPL mode
            await agent.start_repl()

    finally:
        await agent.shutdown()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Modular, Config-Driven MCP Agent Host in Python"
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Model key to set as active (e.g., 'mock/security-agent', 'ollama/qwen2.5:7b', 'openai/gpt-4o')"
    )
    parser.add_argument(
        "--config-dir",
        type=str,
        default="config",
        help="Path to configuration directory (default: 'config')"
    )
    parser.add_argument(
        "--query",
        type=str,
        default=None,
        help="Single prompt or task to run non-interactively"
    )
    parser.add_argument(
        "--auto-approve",
        action="store_true",
        help="Automatically approve Human-in-the-Loop (HITL) tool prompts (useful for headless testing)"
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Automatically compile Markdown and HTML reports after non-interactive query"
    )
    parser.add_argument(
        "--session-id",
        type=str,
        default=None,
        help="Custom session identifier for evidence persistence"
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run an automated end-to-end assessment demo and generate reports"
    )
    parser.add_argument(
        "--ui",
        action="store_true",
        help="Launch the interactive Web Dashboard (FastAPI & SPA UI)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port for Web Dashboard (default: 8000)"
    )

    args = parser.parse_args()

    if args.ui:
        import uvicorn
        print(f"\n🚀 Launching MCP Agent Host Web Dashboard at http://127.0.0.1:{args.port}\n")
        uvicorn.run("ui.app:app", host="127.0.0.1", port=args.port)
        return

    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
