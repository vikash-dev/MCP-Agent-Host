"""
AI Orchestrator & MCP Agent Host
--------------------------------
Coordinates user interaction, dynamic model selection, MCP tool invocation,
policy & scope enforcement, human-in-the-loop approvals, evidence persistence,
and grounded report generation.
"""

import os
import sys
import json
import time
import uuid
import asyncio
from typing import Any, Dict, List, Optional, Tuple
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown

from core.evidence_store import EvidenceStore
from core.guardrails import (
    GuardrailsMiddleware,
    PolicyViolationError,
    ScopeViolationError,
    HITLRejectionError
)
from core.mcp_manager import MCPManager
from core.llm_provider import ModelSwitcher, LLMResponse, ToolCall
from core.reporter import ReportGenerator


class AgentHost:
    """
    Modular MCP Agent Host with dynamic model swapping and plug-and-play tool servers.
    """

    def __init__(
        self,
        config_dir: str = "config",
        active_model: Optional[str] = None,
        auto_approve: bool = False,
        session_id: Optional[str] = None
    ):
        self.config_dir = os.path.abspath(config_dir)
        self.console = Console()
        self.session_id = session_id or f"session_{datetime_slug()}"

        # 1. Initialize Evidence Store & Reporter
        self.evidence_store = EvidenceStore(
            db_path=os.path.join("runs", "evidence.db"),
            runs_dir="runs"
        )
        self.reporter = ReportGenerator(self.evidence_store)

        # 2. Initialize Policy & Guardrails Middleware
        policy_path = os.path.join(self.config_dir, "policy.json")
        self.guardrails = GuardrailsMiddleware(
            policy_path=policy_path,
            auto_approve=auto_approve
        )

        # 3. Initialize Plug-and-Play MCP Registry Manager
        servers_config_path = os.path.join(self.config_dir, "mcp_servers.json")
        self.mcp_manager = MCPManager(config_path=servers_config_path)

        # 4. Initialize Dynamic Model Switcher
        models_config_path = os.path.join(self.config_dir, "models.json")
        self.model_switcher = ModelSwitcher(config_path=models_config_path)
        if active_model:
            self.model_switcher.switch_model(active_model)

        # 5. Session State
        self.messages: List[Dict[str, Any]] = []
        self.evidence_store.start_session(
            session_id=self.session_id,
            model_name=self.model_switcher.active_model_name,
            target_scope=self.guardrails.allowed_domains
        )

    async def initialize(self) -> None:
        """Starts connected MCP servers and loads active tools."""
        await self.mcp_manager.initialize()

    async def run_turn(self, user_input: str, max_iterations: int = 5) -> str:
        """
        Executes a multi-step agent reasoning & tool-execution turn.
        User Input -> LLM -> Tool Calls -> Guardrails -> MCP Execution -> Evidence Log -> LLM Synthesis.
        """
        self.messages.append({"role": "user", "content": user_input})

        final_response_text = ""
        iteration = 0

        while iteration < max_iterations:
            iteration += 1
            client = self.model_switcher.get_client()
            tools_schemas = self.mcp_manager.get_openai_function_schemas()

            # Query the active LLM
            try:
                response: LLMResponse = await client.complete(
                    messages=self.messages,
                    tools=tools_schemas if tools_schemas else None
                )
            except Exception as e:
                err_msg = f"[bold red]LLM Provider Error:[/bold red] {str(e)}"
                self.console.print(err_msg)
                return str(e)

            # Record model response
            if response.content:
                final_response_text = response.content

            # If no tool calls were requested, the model finished its response
            if not response.tool_calls:
                self.messages.append({"role": "assistant", "content": response.content or ""})
                break

            # Handle assistant tool calling message
            assistant_msg: Dict[str, Any] = {
                "role": "assistant",
                "content": response.content or "",
                "tool_calls": [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.name,
                            "arguments": json.dumps(tc.arguments)
                        }
                    } for tc in response.tool_calls
                ]
            }
            self.messages.append(assistant_msg)

            # Execute tool calls sequentially through Guardrails & MCP Manager
            for tc in response.tool_calls:
                self.console.print(
                    f"\n[cyan]⚙️  LLM Tool Call:[/cyan] [bold]{tc.name}[/bold] -> [dim]{json.dumps(tc.arguments)}[/dim]"
                )

                tool_result, status, err = await self._execute_tool_with_guardrails(tc.name, tc.arguments)

                # Append tool response message
                self.messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "name": tc.name,
                    "content": tool_result
                })

        return final_response_text

    async def _execute_tool_with_guardrails(
        self,
        tool_name: str,
        arguments: Dict[str, Any]
    ) -> Tuple[str, str, Optional[str]]:
        """
        Executes a single tool call with scope validation, HITL checks, timeout,
        evidence persistence, and context truncation.
        """
        server_cfg = self.mcp_manager.get_server_config_for_tool(tool_name)
        server_name = server_cfg.get("name", "unknown_server")
        start_time = time.perf_counter()

        # 1. Scope Allowlist Verification
        try:
            self.guardrails.validate_scope(tool_name, arguments)
        except ScopeViolationError as e:
            exec_time = (time.perf_counter() - start_time) * 1000
            err_text = f"Policy Scope Violation: {str(e)}"
            self.console.print(f"[bold red]⛔ {err_text}[/bold red]")
            self.evidence_store.log_tool_invocation(
                session_id=self.session_id,
                server_name=server_name,
                tool_name=tool_name,
                arguments=arguments,
                raw_output={"error": err_text},
                status="REJECTED_SCOPE",
                execution_time_ms=exec_time,
                error_message=err_text
            )
            return json.dumps({"status": "REJECTED_SCOPE", "message": err_text}), "REJECTED_SCOPE", err_text

        # 2. Human-in-the-Loop (HITL) Operator Confirmation
        try:
            self.guardrails.check_hitl_approval(tool_name, arguments, server_cfg)
        except HITLRejectionError as e:
            exec_time = (time.perf_counter() - start_time) * 1000
            err_text = f"HITL Operator Rejection: {str(e)}"
            self.console.print(f"[bold yellow]✋ {err_text}[/bold yellow]")
            self.evidence_store.log_tool_invocation(
                session_id=self.session_id,
                server_name=server_name,
                tool_name=tool_name,
                arguments=arguments,
                raw_output={"error": err_text},
                status="REJECTED_HITL",
                execution_time_ms=exec_time,
                error_message=err_text
            )
            return json.dumps({"status": "REJECTED_HITL", "message": err_text}), "REJECTED_HITL", err_text

        # 3. Execution with Timeout Enforcement
        timeout = self.guardrails.timeout_seconds
        try:
            raw_result = await asyncio.wait_for(
                self.mcp_manager.call_tool(tool_name, arguments, timeout=timeout),
                timeout=timeout + 2.0
            )
            exec_time = (time.perf_counter() - start_time) * 1000
            status = "SUCCESS"
            err_msg = None
        except asyncio.TimeoutError:
            exec_time = (time.perf_counter() - start_time) * 1000
            status = "TIMEOUT"
            err_msg = f"Tool execution timed out after {timeout} seconds."
            raw_result = {"error": err_msg}
            self.console.print(f"[bold red]⏱️  {err_msg}[/bold red]")
        except Exception as e:
            exec_time = (time.perf_counter() - start_time) * 1000
            status = "FAILED"
            err_msg = str(e)
            raw_result = {"error": err_msg}
            self.console.print(f"[bold red]❌ Tool execution failed: {err_msg}[/bold red]")

        # 4. Evidence Persistence
        raw_str = raw_result if isinstance(raw_result, str) else json.dumps(raw_result, indent=2)
        inv_record = self.evidence_store.log_tool_invocation(
            session_id=self.session_id,
            server_name=server_name,
            tool_name=tool_name,
            arguments=arguments,
            raw_output=raw_result,
            status=status,
            execution_time_ms=exec_time,
            error_message=err_msg
        )

        # 5. Output Truncation for LLM Context Window
        artifact_path = inv_record.get("artifact_path")
        safe_output_str, was_truncated = self.guardrails.truncate_output(raw_str, artifact_path=artifact_path)
        if was_truncated:
            self.console.print(f"[dim yellow]✂️  Output truncated for LLM context (preserved in {os.path.basename(artifact_path)})[/dim yellow]")

        return safe_output_str, status, err_msg

    # =========================================================================
    # REPL Interactive Shell & Slash Commands
    # =========================================================================

    async def start_repl(self) -> None:
        """Starts the interactive Agent Host command loop."""
        self._print_welcome_banner()

        while True:
            try:
                prompt_label = f"\n[bold green]MCP-Host ({self.model_switcher.active_model_name})>[/bold green] "
                user_input = self.console.input(prompt_label).strip()

                if not user_input:
                    continue

                # Command Dispatch
                if user_input.startswith("/"):
                    parts = user_input.split()
                    cmd = parts[0].lower()
                    cmd_args = parts[1:]

                    if cmd in ["/exit", "/quit"]:
                        self.console.print("[yellow]Shutting down MCP Host...[/yellow]")
                        break
                    elif cmd == "/model":
                        if not cmd_args:
                            self.console.print(f"Current active model: [bold green]{self.model_switcher.active_model_name}[/bold green]")
                        else:
                            msg = self.model_switcher.switch_model(cmd_args[0])
                            self.console.print(f"[green]✔ {msg}[/green]")
                    elif cmd == "/models":
                        self._display_models_table()
                    elif cmd == "/servers":
                        self._display_servers_table()
                    elif cmd == "/server":
                        if len(cmd_args) >= 2 and cmd_args[0].lower() == "enable":
                            name = cmd_args[1]
                            success = await self.mcp_manager.enable_server(name)
                            if success:
                                self.console.print(f"[green]✔ Server '{name}' enabled and tools registered.[/green]")
                            else:
                                self.console.print(f"[red]✖ Failed to enable server '{name}'.[/red]")
                        elif len(cmd_args) >= 2 and cmd_args[0].lower() == "disable":
                            name = cmd_args[1]
                            await self.mcp_manager.disable_server(name)
                            self.console.print(f"[yellow]✔ Server '{name}' disabled and tools unplugged.[/yellow]")
                        else:
                            self.console.print("[dim]Usage: /server enable <name> | /server disable <name>[/dim]")
                    elif cmd == "/tools":
                        self._display_tools_table()
                    elif cmd == "/policy":
                        self._display_policy()
                    elif cmd == "/report":
                        reports = self.reporter.compile_reports(self.session_id)
                        self.console.print(f"\n[bold green]📄 Reports Generated for Session {self.session_id}:[/bold green]")
                        self.console.print(f"  - Markdown : [cyan]{reports['markdown']}[/cyan]")
                        self.console.print(f"  - HTML     : [cyan]{reports['html']}[/cyan]")
                    elif cmd == "/clear":
                        self.messages.clear()
                        self.console.print("[green]✔ Conversation history cleared.[/green]")
                    elif cmd in ["/help", "/?"]:
                        self._print_help()
                    else:
                        self.console.print(f"[red]Unknown command '{cmd}'. Type /help for options.[/red]")
                    continue

                # Run conversation turn
                self.console.print("[dim]Thinking...[/dim]")
                response_text = await self.run_turn(user_input)
                if response_text:
                    self.console.print("\n[bold purple]🤖 Agent Response:[/bold purple]")
                    self.console.print(Markdown(response_text))

            except (KeyboardInterrupt, EOFError):
                self.console.print("\n[yellow]Exiting MCP Host session...[/yellow]")
                break
            except Exception as e:
                self.console.print(f"[bold red]Unexpected Error:[/bold red] {e}")

        # Graceful cleanup
        await self.shutdown()

    def _print_welcome_banner(self) -> None:
        self.console.print(Panel(
            f"[bold cyan]Modular Config-Driven MCP Agent Host[/bold cyan]\n"
            f"[dim]Active LLM: [bold white]{self.model_switcher.active_model_name}[/bold white] | "
            f"Session ID: [bold white]{self.session_id}[/bold white][/dim]\n"
            f"[dim]Commands: [green]/model <name>[/green] to switch model, [green]/servers[/green] to inspect MCPs, [green]/report[/green] to compile findings, [green]/help[/green] for menu.[/dim]",
            border_style="cyan"
        ))

    def _print_help(self) -> None:
        help_table = Table(title="Interactive Slash Commands", border_style="dim")
        help_table.add_column("Command", style="cyan bold")
        help_table.add_column("Description", style="white")
        help_table.add_row("/model <name>", "Switch active LLM at runtime without restarting MCP servers")
        help_table.add_row("/models", "List all configured models (Ollama, OpenAI, Mock)")
        help_table.add_row("/servers", "Display registered MCP servers & live status")
        help_table.add_row("/server enable <name>", "Plug in and connect an MCP server dynamically")
        help_table.add_row("/server disable <name>", "Unplug and disconnect an MCP server dynamically")
        help_table.add_row("/tools", "List all discovered tools across connected MCP servers")
        help_table.add_row("/policy", "Display active target scope allowlists and safety limits")
        help_table.add_row("/report", "Compile Markdown and HTML security assessment reports")
        help_table.add_row("/clear", "Clear session conversation messages")
        help_table.add_row("/exit, /quit", "Gracefully terminate the agent host")
        self.console.print(help_table)

    def _display_models_table(self) -> None:
        table = Table(title="Configured LLM Models", border_style="dim")
        table.add_column("Model Key", style="cyan bold")
        table.add_column("Provider", style="magenta")
        table.add_column("Active", style="green")
        table.add_column("Description", style="dim")
        for m in self.model_switcher.list_models():
            active_marker = "✔ ACTIVE" if m["is_active"] else ""
            table.add_row(m["key"], m["provider"], active_marker, m["description"])
        self.console.print(table)

    def _display_servers_table(self) -> None:
        table = Table(title="MCP Server Registry", border_style="dim")
        table.add_column("Server Name", style="cyan bold")
        table.add_column("Transport", style="blue")
        table.add_column("Enabled", style="magenta")
        table.add_column("Connected", style="green")
        table.add_column("Tools Discovered", style="yellow")
        table.add_column("HITL Required", style="red")
        for s in self.mcp_manager.list_servers():
            table.add_row(
                s["name"],
                s["transport"],
                "Yes" if s["enabled"] else "No",
                "Connected" if s["connected"] else "Disconnected",
                str(s["tool_count"]),
                "Yes" if s["requires_approval"] else "No"
            )
        self.console.print(table)

    def _display_tools_table(self) -> None:
        table = Table(title="Discovered MCP Tools", border_style="dim")
        table.add_column("Tool Name", style="cyan bold")
        table.add_column("Server", style="magenta")
        table.add_column("Description", style="white")
        for t in self.mcp_manager.get_all_tools():
            table.add_row(t.get("name", ""), t.get("server_name", ""), t.get("description", ""))
        self.console.print(table)

    def _display_policy(self) -> None:
        self.console.print(Panel(
            f"[bold]Active Target Scope Allowlist:[/bold]\n"
            f"  - Allowed Domains: {self.guardrails.allowed_domains}\n"
            f"  - Allowed CIDRs:   {self.guardrails.allowed_cidrs}\n"
            f"  - Allowed Paths:   {self.guardrails.allowed_paths}\n\n"
            f"[bold]Execution Limits:[/bold]\n"
            f"  - Timeout Seconds: {self.guardrails.timeout_seconds}s\n"
            f"  - Max Output Chars: {self.guardrails.max_output_chars} chars\n\n"
            f"[bold]Human-in-the-Loop (HITL) Sensitive Tools:[/bold]\n"
            f"  - {self.guardrails.sensitive_tools}",
            title="Policy & Scope Guardrails",
            border_style="yellow"
        ))

    async def shutdown(self) -> None:
        """Terminates MCP servers and updates session status in Evidence Store."""
        await self.mcp_manager.shutdown()
        self.evidence_store.update_session(self.session_id, status="COMPLETED")


def datetime_slug() -> str:
    import datetime
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
