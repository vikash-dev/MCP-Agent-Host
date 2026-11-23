"""
End-to-End Integration Tests for MCP Agent Host.
"""

import os
import json
import pytest
from core.agent import AgentHost


@pytest.mark.asyncio
async def test_end_to_end_agent_flow(tmp_path):
    # Initialize AgentHost with mock model and auto-approve enabled
    agent = AgentHost(
        config_dir="config",
        active_model="mock/security-agent",
        auto_approve=True,
        session_id=f"test_session_{tmp_path.name}"
    )

    try:
        await agent.initialize()

        # Verify initial active model & tools
        assert agent.model_switcher.active_model_name == "mock/security-agent"
        tools = agent.mcp_manager.get_all_tools()
        assert len(tools) >= 3

        # Execute Multi-Step Assessment Turn
        query = "Analyze audit log at sample_data/audit_sample.log"
        response_text = await agent.run_turn(query)

        assert "Security Assessment Synthesis" in response_text
        assert "Audit Log Inspection" in response_text

        # Verify Evidence Store persistence
        invocations = agent.evidence_store.get_session_invocations(agent.session_id)
        assert len(invocations) >= 1
        assert invocations[0]["tool_name"] == "analyze_audit_log"
        assert invocations[0]["status"] == "SUCCESS"
        assert os.path.exists(invocations[0]["raw_output_path"])

        # Verify Findings table
        findings = agent.evidence_store.get_session_findings(agent.session_id)
        assert len(findings) >= 1

        # DYNAMIC MODEL SWITCHING TEST (without restarting MCP connections!)
        initial_server_pids = {
            name: client.process.pid for name, client in agent.mcp_manager.clients.items()
            if hasattr(client, "process") and client.process
        }

        # Switch to ollama model
        agent.model_switcher.switch_model("ollama/mistral:7b")
        assert agent.model_switcher.active_model_name == "ollama/mistral:7b"

        # Verify MCP server process is still alive and identical PID!
        for name, pid in initial_server_pids.items():
            current_client = agent.mcp_manager.clients.get(name)
            assert current_client is not None
            assert current_client.process.pid == pid

        # Switch back to mock
        agent.model_switcher.switch_model("mock/security-agent")
        assert agent.model_switcher.active_model_name == "mock/security-agent"

        # Generate Grounded Reports
        reports = agent.reporter.compile_reports(agent.session_id)
        assert os.path.exists(reports["markdown"])
        assert os.path.exists(reports["html"])

        with open(reports["markdown"], "r", encoding="utf-8") as f:
            md = f.read()
            assert "Automated Security Assessment Report" in md
            assert "Audit Log Inspection" in md or "Executive Summary" in md

    finally:
        await agent.shutdown()
