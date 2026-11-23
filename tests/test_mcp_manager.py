"""
Tests for Plug-and-Play MCP Server Registry & Routing.
"""

import os
import sys
import json
import pytest
from core.mcp_manager import MCPManager


@pytest.fixture
def mcp_config(tmp_path):
    cfg_data = {
      "servers": {
        "security_inspector": {
          "name": "security_inspector",
          "description": "Defensive inspector",
          "transport": "stdio",
          "command": sys.executable,
          "args": ["-m", "servers.sample_inspector_mcp"],
          "cwd": ".",
          "enabled": True,
          "requires_approval": False,
          "tools_require_approval": ["inspect_tls_cert"]
        },
        "remote_audit_feed": {
          "name": "remote_audit_feed",
          "description": "Remote audit SSE server",
          "transport": "sse",
          "url": "http://127.0.0.1:8080/sse",
          "enabled": False,
          "requires_approval": True,
          "tools_require_approval": []
        }
      }
    }
    cfg_file = tmp_path / "mcp_servers.json"
    cfg_file.write_text(json.dumps(cfg_data, indent=2), encoding="utf-8")
    return str(cfg_file)


@pytest.mark.asyncio
async def test_mcp_manager_discovery_and_call(mcp_config):
    manager = MCPManager(config_path=mcp_config)
    await manager.initialize()

    try:
        # Check registered servers
        servers = manager.list_servers()
        assert len(servers) == 2
        active_srv = [s for s in servers if s["connected"]]
        assert len(active_srv) == 1
        assert active_srv[0]["name"] == "security_inspector"

        # Check discovered tools
        tools = manager.get_all_tools()
        tool_names = [t["name"] for t in tools]
        assert "check_security_headers" in tool_names
        assert "analyze_audit_log" in tool_names
        assert "inspect_tls_cert" in tool_names

        # Check OpenAI function schemas
        schemas = manager.get_openai_function_schemas()
        assert len(schemas) == 3
        assert all(s["type"] == "function" for s in schemas)
        assert any(s["function"]["name"] == "analyze_audit_log" for s in schemas)

        # Execute read-only tool
        res = await manager.call_tool(
            "analyze_audit_log",
            {"log_path": "sample_data/audit_sample.log"}
        )
        assert res is not None
        assert "matched_events_count" in str(res)

    finally:
        await manager.shutdown()


@pytest.mark.asyncio
async def test_dynamic_plug_and_play(mcp_config):
    manager = MCPManager(config_path=mcp_config)
    await manager.initialize()

    try:
        # Remote audit feed starts disabled
        assert "remote_audit_feed" not in manager.clients

        # Dynamically plug in (enable) remote_audit_feed
        success = await manager.enable_server("remote_audit_feed")
        assert success
        assert "remote_audit_feed" in manager.clients

        # Verify new tool was automatically discovered and added to schemas
        schemas = manager.get_openai_function_schemas()
        schema_names = [s["function"]["name"] for s in schemas]
        assert "remote_compliance_audit" in schema_names

        # Execute dynamically plugged-in tool
        res = await manager.call_tool("remote_compliance_audit", {"framework": "SOC2"})
        assert "REMOTE_MOCK_SUCCESS" in str(res)

        # Dynamically unplug (disable) remote_audit_feed
        await manager.disable_server("remote_audit_feed")
        assert "remote_audit_feed" not in manager.clients

        # Verify tool was removed
        updated_schemas = manager.get_openai_function_schemas()
        updated_names = [s["function"]["name"] for s in updated_schemas]
        assert "remote_compliance_audit" not in updated_names

    finally:
        await manager.shutdown()
