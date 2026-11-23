"""
Tests for MCP Agent Host Web UI API.
"""

import pytest
from fastapi.testclient import TestClient
from ui.app import app, get_agent


@pytest.fixture
def client():
    # Ensure agent is initialized
    agent = get_agent()
    with TestClient(app) as test_client:
        yield test_client


def test_dashboard_page(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "MCP Agent Host" in res.text
    assert "Agent Workspace" in res.text


def test_api_status(client):
    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ONLINE"
    assert "active_model" in data
    assert "session_id" in data
    assert "policy" in data


def test_models_api(client):
    # List models
    res = client.get("/api/models")
    assert res.status_code == 200
    data = res.json()
    assert "models" in data
    assert len(data["models"]) >= 4

    # Switch model to mock
    switch_res = client.post("/api/models/switch", json={"model_name": "mock/security-agent"})
    assert switch_res.status_code == 200
    assert switch_res.json()["active_model"] == "mock/security-agent"

    # Register new model
    add_res = client.post("/api/models/add", json={
        "model_key": "ollama/test-model:latest",
        "provider": "ollama",
        "model_name": "test-model:latest",
        "description": "Test model registration"
    })
    assert add_res.status_code == 200


def test_servers_and_tools_api(client):
    # Servers list
    res = client.get("/api/servers")
    assert res.status_code == 200
    servers = res.json()
    assert len(servers) >= 2

    # Toggle server
    toggle_res = client.post("/api/servers/toggle", json={"name": "network_recon_mock", "enabled": True})
    assert toggle_res.status_code == 200
    assert toggle_res.json()["enabled"] is True

    # Disable again
    toggle_off = client.post("/api/servers/toggle", json={"name": "network_recon_mock", "enabled": False})
    assert toggle_off.status_code == 200

    # Tools list
    tools_res = client.get("/api/tools")
    assert tools_res.status_code == 200


def test_policy_api(client):
    # Get policy
    res = client.get("/api/policy")
    assert res.status_code == 200
    policy = res.json()
    assert "scope" in policy
    assert "allowed_domains" in policy["scope"]

    # Update policy
    update_res = client.post("/api/policy", json={
        "allowed_domains": ["example.com", "test.corp"],
        "allowed_cidrs": ["10.0.0.0/8"],
        "allowed_paths": ["./sample_data", "./runs"],
        "timeout_seconds": 25,
        "max_output_chars": 5000,
        "sensitive_tools": ["inspect_tls_cert"]
    })
    assert update_res.status_code == 200
    assert update_res.json()["policy"]["execution_limits"]["timeout_seconds"] == 25


def test_chat_interaction_and_report_api(client):
    # Ensure active model is mock for deterministic testing
    client.post("/api/models/switch", json={"model_name": "mock/security-agent"})

    # Send chat query
    chat_res = client.post("/api/chat", json={
        "message": "Analyze audit log at sample_data/audit_sample.log",
        "auto_approve": True
    })
    assert chat_res.status_code == 200
    chat_data = chat_res.json()
    assert "response" in chat_data
    assert "session_id" in chat_data
    assert "Security Assessment Synthesis" in chat_data["response"]

    # Generate and fetch reports
    session_id = chat_data["session_id"]
    report_res = client.get(f"/api/sessions/{session_id}/report")
    assert report_res.status_code == 200
    report_data = report_res.json()
    assert "markdown_content" in report_data
    assert "Executive Summary" in report_data["markdown_content"]

    # View HTML report
    html_res = client.get(f"/api/sessions/{session_id}/report/html")
    assert html_res.status_code == 200
    assert "<!DOCTYPE html>" in html_res.text
