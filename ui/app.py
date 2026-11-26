"""
MCP Agent Host - Web UI Backend (FastAPI)
-----------------------------------------
Provides a modern REST API and interactive Web Dashboard for:
  - Agent Chat with live tool invocation breakdown
  - Dynamic runtime Model Switching (Ollama, OpenAI, Mock)
  - Plug-and-Play MCP Server Management (one-click toggle & registration)
  - Target Scope & Guardrail Policy Configuration
  - Human-in-the-Loop (HITL) Operator Approval Controls
  - Evidence Store Browser & Grounded Report Viewer (Markdown/HTML)
"""

import os
import sys
import json
import time
import asyncio
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from core.agent import AgentHost
from core.evidence_store import EvidenceStore
from core.guardrails import GuardrailsMiddleware
from core.mcp_manager import MCPManager
from core.llm_provider import ModelSwitcher
from core.reporter import ReportGenerator


# Global State
agent_host: Optional[AgentHost] = None
pending_hitl_approvals: Dict[str, asyncio.Event] = {}
hitl_results: Dict[str, bool] = {}


def get_agent() -> AgentHost:
    global agent_host
    if agent_host is None:
        agent_host = AgentHost(
            config_dir="config",
            auto_approve=True  # Can be toggled per request or via UI
        )
    return agent_host


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    agent = get_agent()
    await agent.initialize()
    yield
    # Shutdown
    global agent_host
    if agent_host:
        await agent_host.shutdown()


app = FastAPI(
    title="MCP Agent Host Dashboard",
    description="Interactive Web UI for Model Context Protocol Agent Host",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# Request / Response Schemas
# ============================================================================

class ChatRequest(BaseModel):
    message: str
    auto_approve: bool = True
    session_id: Optional[str] = None


class ModelSwitchRequest(BaseModel):
    model_name: str


class AddModelRequest(BaseModel):
    model_key: str
    provider: str
    model_name: str
    temperature: float = 0.2
    max_tokens: int = 4096
    context_window: int = 32768
    description: str = ""


class ServerToggleRequest(BaseModel):
    name: str
    enabled: bool


class AddServerRequest(BaseModel):
    name: str
    description: str = ""
    transport: str = "stdio"
    command: str = "python"
    args: List[str] = Field(default_factory=list)
    url: str = ""
    cwd: str = "."
    enabled: bool = True
    requires_approval: bool = False
    tools_require_approval: List[str] = Field(default_factory=list)


class PolicyUpdateRequest(BaseModel):
    allowed_domains: List[str]
    allowed_cidrs: List[str]
    allowed_paths: List[str]
    timeout_seconds: int = 30
    max_output_chars: int = 4000
    sensitive_tools: List[str] = Field(default_factory=list)


class HITLResponseRequest(BaseModel):
    approval_id: str
    approved: bool


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/api/status")
async def get_system_status():
    agent = get_agent()
    servers = agent.mcp_manager.list_servers()
    tools = agent.mcp_manager.get_all_tools()
    connected_servers = [s for s in servers if s["connected"]]

    return {
        "status": "ONLINE",
        "active_model": agent.model_switcher.active_model_name,
        "session_id": agent.session_id,
        "servers_total": len(servers),
        "servers_connected": len(connected_servers),
        "tools_count": len(tools),
        "policy": {
            "allowed_domains": agent.guardrails.allowed_domains,
            "allowed_cidrs": agent.guardrails.allowed_cidrs,
            "timeout_seconds": agent.guardrails.timeout_seconds,
            "max_output_chars": agent.guardrails.max_output_chars
        }
    }


# Models Endpoints
@app.get("/api/models")
async def list_models():
    agent = get_agent()
    return {
        "active_model": agent.model_switcher.active_model_name,
        "models": agent.model_switcher.list_models()
    }


@app.post("/api/models/ollama/sync")
async def sync_ollama_models():
    agent = get_agent()
    updated_models = agent.model_switcher.sync_installed_ollama_models()
    return {
        "status": "SUCCESS",
        "active_model": agent.model_switcher.active_model_name,
        "models": updated_models
    }


@app.post("/api/models/switch")
async def switch_model(req: ModelSwitchRequest):
    agent = get_agent()
    try:
        msg = agent.model_switcher.switch_model(req.model_name)
        # Update session model name
        agent.evidence_store.update_session(agent.session_id, summary=f"Switched model to {req.model_name}")
        return {"status": "SUCCESS", "message": msg, "active_model": agent.model_switcher.active_model_name}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/models/add")
async def add_model(req: AddModelRequest):
    agent = get_agent()
    cfg = agent.model_switcher.config_data
    cfg["models"][req.model_key] = {
        "provider": req.provider,
        "model_name": req.model_name,
        "temperature": req.temperature,
        "max_tokens": req.max_tokens,
        "context_window": req.context_window,
        "description": req.description
    }
    with open(agent.model_switcher.config_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)

    return {"status": "SUCCESS", "message": f"Model '{req.model_key}' registered successfully."}


# Servers Endpoints
@app.get("/api/servers")
async def list_servers():
    agent = get_agent()
    servers = agent.mcp_manager.list_servers()
    # Add tools per server
    tools = agent.mcp_manager.get_all_tools()
    for s in servers:
        s["tools"] = [t for t in tools if t.get("server_name") == s["name"]]
    return servers


@app.post("/api/servers/toggle")
async def toggle_server(req: ServerToggleRequest):
    agent = get_agent()
    if req.enabled:
        success = await agent.mcp_manager.enable_server(req.name)
    else:
        success = await agent.mcp_manager.disable_server(req.name)

    if not success:
        raise HTTPException(status_code=400, detail=f"Failed to toggle server '{req.name}'")

    return {
        "status": "SUCCESS",
        "name": req.name,
        "enabled": req.enabled,
        "tools_count": len(agent.mcp_manager.get_all_tools())
    }


@app.post("/api/servers/add")
async def add_server(req: AddServerRequest):
    agent = get_agent()
    srv_dict = {
        "name": req.name,
        "description": req.description,
        "transport": req.transport,
        "command": req.command,
        "args": req.args,
        "url": req.url,
        "cwd": req.cwd,
        "enabled": req.enabled,
        "requires_approval": req.requires_approval,
        "tools_require_approval": req.tools_require_approval
    }
    agent.mcp_manager.server_configs[req.name] = srv_dict
    agent.mcp_manager.save_config()

    if req.enabled:
        await agent.mcp_manager.enable_server(req.name)

    return {"status": "SUCCESS", "message": f"Server '{req.name}' added."}


# Tools Endpoints
@app.get("/api/tools")
async def list_tools():
    agent = get_agent()
    return agent.mcp_manager.get_all_tools()


# Policy Endpoints
@app.get("/api/policy")
async def get_policy():
    agent = get_agent()
    return agent.guardrails.policy


@app.post("/api/policy")
async def update_policy(req: PolicyUpdateRequest):
    agent = get_agent()
    new_policy = {
        "policy_name": agent.guardrails.policy.get("policy_name", "Host Safety Policy"),
        "version": agent.guardrails.policy.get("version", "1.0.0"),
        "scope": {
            "allowed_domains": req.allowed_domains,
            "allowed_cidrs": req.allowed_cidrs,
            "allowed_paths": req.allowed_paths
        },
        "execution_limits": {
            "timeout_seconds": req.timeout_seconds,
            "max_output_chars": req.max_output_chars
        },
        "human_in_the_loop": {
            "default_requires_approval": agent.guardrails.policy.get("human_in_the_loop", {}).get("default_requires_approval", False),
            "sensitive_tools": req.sensitive_tools
        }
    }
    agent.guardrails.policy = new_policy
    with open(agent.guardrails.policy_path, "w", encoding="utf-8") as f:
        json.dump(new_policy, f, indent=2)

    return {"status": "SUCCESS", "policy": new_policy}


# Chat Endpoint
@app.post("/api/chat")
async def chat_interaction(req: ChatRequest):
    agent = get_agent()
    agent.guardrails.auto_approve = req.auto_approve

    if req.session_id and req.session_id != agent.session_id:
        agent.session_id = req.session_id
        agent.evidence_store.start_session(agent.session_id, agent.model_switcher.active_model_name)

    # Capture invocations before turn
    before_inv_count = len(agent.evidence_store.get_session_invocations(agent.session_id))

    response_text = await agent.run_turn(req.message)

    # Fetch new invocations generated during turn
    all_invs = agent.evidence_store.get_session_invocations(agent.session_id)
    new_invs = all_invs[before_inv_count:]

    # Fetch findings
    findings = agent.evidence_store.get_session_findings(agent.session_id)

    return {
        "response": response_text,
        "session_id": agent.session_id,
        "active_model": agent.model_switcher.active_model_name,
        "invocations": new_invs,
        "findings_count": len(findings)
    }


# Sessions & Reports Endpoints
@app.get("/api/sessions")
async def list_sessions():
    agent = get_agent()
    with agent.evidence_store._get_connection() as conn:
        rows = conn.execute("SELECT * FROM sessions ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]


@app.get("/api/sessions/{session_id}")
async def get_session_details(session_id: str):
    agent = get_agent()
    session = agent.evidence_store.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    invocations = agent.evidence_store.get_session_invocations(session_id)
    findings = agent.evidence_store.get_session_findings(session_id)

    return {
        "session": session,
        "invocations": invocations,
        "findings": findings
    }


@app.get("/api/sessions/{session_id}/report")
async def generate_and_get_reports(session_id: str):
    agent = get_agent()
    reports = agent.reporter.compile_reports(session_id)

    md_content = ""
    if os.path.exists(reports["markdown"]):
        with open(reports["markdown"], "r", encoding="utf-8") as f:
            md_content = f.read()

    return {
        "session_id": session_id,
        "markdown_path": reports["markdown"],
        "html_path": reports["html"],
        "markdown_content": md_content,
        "html_url": f"/api/sessions/{session_id}/report/html"
    }


@app.get("/api/sessions/{session_id}/report/html")
async def view_html_report(session_id: str):
    agent = get_agent()
    html_path = os.path.join(agent.evidence_store.runs_dir, session_id, "report.html")
    if not os.path.exists(html_path):
        agent.reporter.generate_html_report(session_id)
    if not os.path.exists(html_path):
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(html_path, media_type="text/html")


@app.get("/api/sessions/{session_id}/report/markdown")
async def download_markdown_report(session_id: str):
    agent = get_agent()
    md_path = os.path.join(agent.evidence_store.runs_dir, session_id, "report.md")
    if not os.path.exists(md_path):
        agent.reporter.generate_markdown_report(session_id)
    if not os.path.exists(md_path):
        raise HTTPException(status_code=404, detail="Markdown report not found")
    return FileResponse(md_path, media_type="text/markdown", filename=f"{session_id}_report.md")


@app.get("/api/artifacts/{session_id}/{filename}")
async def get_raw_artifact(session_id: str, filename: str):
    agent = get_agent()
    path = os.path.join(agent.evidence_store.runs_dir, session_id, "artifacts", filename)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Artifact file not found")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# Root Dashboard Page
@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    template_path = os.path.join(os.path.dirname(__file__), "templates", "index.html")
    if not os.path.exists(template_path):
        return HTMLResponse("<h1>Dashboard template not found</h1>", status_code=500)
    with open(template_path, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())


from markdown_it import MarkdownIt

md_parser = MarkdownIt('commonmark').enable('table')


def _render_doc_page(title: str, md_path: str, doc_type: str = "user") -> HTMLResponse:
    if not os.path.exists(md_path):
        raise HTTPException(status_code=404, detail="Document not found")
    with open(md_path, "r", encoding="utf-8") as f:
        md_text = f.read()
    
    # Pre-render markdown to HTML on server for 100% reliable, instant display
    rendered_body = md_parser.render(md_text)

    template_path = os.path.join(os.path.dirname(__file__), "templates", "doc_page.html")
    if not os.path.exists(template_path):
        raise HTTPException(status_code=500, detail="Documentation template not found")
    with open(template_path, "r", encoding="utf-8") as f:
        tpl_str = f.read()

    from jinja2 import Template
    tpl = Template(tpl_str)
    rendered_html = tpl.render(
        title=title,
        doc_type=doc_type,
        rendered_content=rendered_body,
        md_json=json.dumps(md_text)
    )
    return HTMLResponse(rendered_html)


@app.get("/docs/user-guide", response_class=HTMLResponse)
async def view_user_guide():
    doc_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "docs", "USER_GUIDE.md")
    return _render_doc_page("User Guide", doc_path, doc_type="user")


@app.get("/docs/developer-guide", response_class=HTMLResponse)
async def view_developer_guide():
    doc_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "docs", "DEVELOPER_GUIDE.md")
    return _render_doc_page("Developer Guide", doc_path, doc_type="dev")
