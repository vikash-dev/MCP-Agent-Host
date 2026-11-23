# Modular, Config-Driven MCP Agent Host

A robust, enterprise-grade **Model Context Protocol (MCP)** Agent Host in Python supporting **dynamic runtime LLM model switching** (OpenAI endpoints, local Ollama models like Qwen 2.5, Mistral, Gemma 2) and **plug-and-play MCP server registration** with strict defensive guardrails, structured evidence auditing, and automated report generation.

The system architecture mirrors the high-level layered separation established in [AI_Pentesting_Architecture_A4.pdf](file:///d:/AIexperiments/AIenabPTtool/AI_Pentesting_Architecture_A4.pdf):
1. **User & Configuration Layer**: Scope allowlists, scan policies, report formatting, and Human-in-the-Loop (HITL) gates.
2. **AI Orchestrator & Model Swapper**: Runtime LLM switching, planning, and multi-turn tool-calling reasoning.
3. **MCP Client/Server Interface**: Dynamic stdio and SSE/HTTP server lifecycle with schema translation.
4. **Evidence Store & Artifacts**: SQLite database and filesystem raw artifact capture.
5. **Grounded Report Generation**: Executive summary, findings breakdown, and audit trails in Markdown and HTML.

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       1. USER & CONFIGURATION LAYER                         │
│  Target Scope (Allowlists) │ Scan Policy (Safety Gates) │ HITL Approval Gate │
│  config/policy.json        │ config/models.json         │ config/mcp_servers │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                 2. AI ORCHESTRATOR & DYNAMIC MODEL SWAPPER                  │
│   Unified LLM Client Interface (Ollama Qwen/Mistral/Gemma, OpenAI, Mock)   │
│   Runtime Swapper (/model <name>) ── Persists active MCP connections       │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│              3. MCP CLIENT / SERVER INTERFACE & REGISTRY                    │
│   Plug-and-Play MCP Registry (enabled: true/false toggle)                  │
│   stdio Transport (Subprocess JSON-RPC) │ SSE / HTTP Transport             │
│   Auto-discovery (tools/list) ── Function Schema Translation (tools/call)   │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│               4. EVIDENCE STORE & RAW ARTIFACT PERSISTENCE                  │
│   Structured SQLite Database (runs/evidence.db)                             │
│   Full Untruncated Session Artifacts (runs/<session_id>/artifacts/*.json)   │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                  5. GROUNDED REPORT GENERATOR                               │
│   Executive Summary │ Scope & Policy │ Discovered Findings Table            │
│   Evidence References │ Remediation Roadmap (Markdown & Styled HTML)        │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Directory Structure

```
AIenabPTtool/
├── config/
│   ├── models.json              # Model profiles & active LLM pointer
│   ├── mcp_servers.json         # Plug-and-play MCP server registry
│   └── policy.json              # Target scope allowlists, timeouts & HITL gates
├── core/
│   ├── __init__.py              # Package exports
│   ├── llm_provider.py          # Unified LLM provider & dynamic model switcher
│   ├── mcp_manager.py           # MCP server registry, transports & tool router
│   ├── guardrails.py            # Policy scope middleware, timeouts, HITL & truncation
│   ├── evidence_store.py        # SQLite persistence & artifact storage
│   ├── reporter.py              # Grounded Markdown & HTML report generator
│   └── agent.py                 # AI orchestrator & interactive REPL shell
├── sample_data/
│   └── audit_sample.log         # Sample audit event log for testing
├── servers/
│   ├── __init__.py
│   └── sample_inspector_mcp.py  # Reference safe stdio MCP server
├── tests/
│   ├── __init__.py
│   ├── test_guardrails.py       # Scope, CIDR, path, HITL, truncation tests
│   ├── test_evidence_and_report.py # SQLite & report generation tests
│   ├── test_llm_provider.py     # Model switching & mock client tests
│   ├── test_mcp_manager.py      # Stdio discovery, plug/unplug & routing tests
│   └── test_e2e_agent.py        # End-to-end integration test
├── ui/
│   ├── __init__.py              # Web UI package
│   ├── app.py                   # FastAPI REST backend & SSE/WebSocket handlers
│   └── templates/
│       └── index.html           # Modern Tailwind CSS Single-Page Application (SPA)
├── ui.py                        # Web UI Dashboard standalone launcher
├── runs/                        # Session artifacts, reports & evidence.db
├── main.py                      # CLI entry point (REPL & Web UI mode)
├── pyproject.toml               # Project metadata & packaging
├── pytest.ini                   # Asyncio test configuration
├── requirements.txt             # Dependency specifications
└── README.md                    # System documentation
```

---

## Quickstart & Launching the Web UI

### 1. Installation

Activate your virtual environment and install dependencies:

```bash
# Using pip
pip install -r requirements.txt

# Or install in editable mode
pip install -e .
```

### 2. Launch the Interactive Mission Control Web Dashboard

For the best user experience, launch the graphical Web UI:

```bash
python ui.py
# Or using main.py
python main.py --ui
```

Open your browser to **`http://127.0.0.1:8000`** to access:
- 💬 **Agent Workspace**: Live conversational agent, real-time tool execution cards, quick prompt chips, and full raw artifact inspectors.
- 🧠 **Dynamic Model Swapper**: Visual cards for Ollama (`qwen2.5`, `mistral`, `gemma2`), OpenAI (`gpt-4o`), and deterministic Mock models. Switch models with one click without resetting active MCP connections!
- 🔌 **Plug-and-Play MCP Registry**: Live server cards with one-click **Enable / Disable toggles** (unplug/plug servers on demand), parameter schemas, and server registration modals.
- 🛡️ **Scope & Guardrails Editor**: Real-time management of domain allowlists, CIDR blocks, authorized file paths, timeouts, and sensitive tools.
- 📊 **Evidence Store & Grounded Reports**: Discovered findings breakdown with severity badges, raw artifact drawer, in-app HTML report viewer, and instant Markdown download.

---

### 3. Run the Automated CLI Demo (Non-Interactive)

Run the end-to-end assessment demo to verify the host, sample MCP server, evidence store, and report compiler:

```bash
python main.py --demo --auto-approve
```

This will:
1. Connect to the `security_inspector` MCP server over stdio.
2. Execute a defensive assessment of HTTP headers and audit logs.
3. Record all raw tool outputs in `runs/<session_id>/artifacts/`.
4. Persist structured findings in `runs/evidence.db`.
5. Compile `report.md` and `report.html`.

### 3. Start the Interactive Agent REPL

Launch the interactive console host:

```bash
python main.py
```

Inside the REPL, you can interact naturally with the agent or run slash commands:

```
MCP-Host (ollama/qwen2.5:7b)> /help
MCP-Host (ollama/qwen2.5:7b)> /servers
MCP-Host (ollama/qwen2.5:7b)> /tools
MCP-Host (ollama/qwen2.5:7b)> /model mock/security-agent
MCP-Host (mock/security-agent)> Analyze security headers for https://example.com
MCP-Host (mock/security-agent)> /report
```

---

## Dynamic Model Switcher (`core/llm_provider.py`)

The dynamic model switcher allows swapping the active reasoning model at runtime **without dropping or restarting existing MCP server connections**.

### Switching Models at Runtime

You can switch the model via:
1. **Interactive REPL command**:
   ```
   /model ollama/mistral:7b
   /model openai/gpt-4o
   /model mock/security-agent
   ```
2. **CLI flag**:
   ```bash
   python main.py --model ollama/qwen2.5:7b
   ```
3. **Configuration file**: Changing `"active_model"` in [config/models.json](file:///d:/AIexperiments/AIenabPTtool/config/models.json).

### How to Add a New Model

Open [config/models.json](file:///d:/AIexperiments/AIenabPTtool/config/models.json):

1. **Add a local Ollama model** (e.g. `llama3.3:70b`):
   ```json
   "models": {
     "ollama/llama3.3:70b": {
       "provider": "ollama",
       "model_name": "llama3.3:70b",
       "temperature": 0.2,
       "max_tokens": 8192,
       "context_window": 65536,
       "description": "Meta Llama 3.3 70B Instruct via local Ollama"
     }
   }
   ```
2. **Add a custom OpenAI-compatible model** (e.g. vLLM or LMStudio):
   ```json
   "providers": {
     "vllm_local": {
       "type": "openai_compatible",
       "base_url": "http://192.168.1.50:8000/v1",
       "api_key": "token-xyz",
       "description": "Private vLLM cluster"
     }
   },
   "models": {
     "vllm/qwen2.5-coder": {
       "provider": "vllm_local",
       "model_name": "Qwen/Qwen2.5-Coder-32B-Instruct",
       "temperature": 0.1,
       "max_tokens": 4096,
       "description": "Self-hosted Qwen 2.5 Coder"
     }
   }
   ```

---

## Plug-and-Play MCP Server Registry (`core/mcp_manager.py`)

The host dynamically discovers tools from any registered MCP server, converts their JSON schemas into standard LLM function-calling definitions, and routes tool calls to the appropriate server.

### Dynamically Plugging and Unplugging Servers

Inside the REPL, servers can be enabled or disabled on demand:
```
/server enable network_recon_mock
/server disable network_recon_mock
```
- Disabling a server immediately revokes its tools from the LLM prompt context and gracefully terminates its subprocess.
- Enabling a server spawns the subprocess, performs the MCP handshake (`initialize` -> `notifications/initialized`), discovers tools (`tools/list`), and registers them with the active LLM.

### How to Add a New MCP Server

Edit [config/mcp_servers.json](file:///d:/AIexperiments/AIenabPTtool/config/mcp_servers.json):

#### 1. Local Python / Node Server (stdio transport)
```json
"custom_pcap_analyzer": {
  "name": "custom_pcap_analyzer",
  "description": "Inspects network PCAP files for anomalies",
  "transport": "stdio",
  "command": "python",
  "args": ["-m", "servers.pcap_analyzer_mcp"],
  "cwd": ".",
  "enabled": true,
  "requires_approval": false,
  "tools_require_approval": ["deep_packet_inspection"]
}
```

#### 2. Node.js MCP Server via npx
```json
"filesystem_mcp": {
  "name": "filesystem_mcp",
  "description": "Local file inspection server",
  "transport": "stdio",
  "command": "npx",
  "args": ["-y", "@modelcontextprotocol/server-filesystem", "./logs"],
  "enabled": false,
  "requires_approval": true
}
```

#### 3. Remote Server (SSE / HTTP transport)
```json
"enterprise_asset_feed": {
  "name": "enterprise_asset_feed",
  "description": "Remote inventory compliance feed",
  "transport": "sse",
  "url": "https://assets.internal.corp/mcp/sse",
  "headers": {
    "Authorization": "Bearer ${CORP_TOKEN}"
  },
  "enabled": false,
  "requires_approval": true
}
```

---

## Policy, Scope & Human-in-the-Loop Guardrails (`core/guardrails.py`)

The host enforces safety boundaries defined in [config/policy.json](file:///d:/AIexperiments/AIenabPTtool/config/policy.json):

```json
{
  "policy_name": "Host Defense & Assessment Scope Policy",
  "scope": {
    "allowed_domains": ["localhost", "127.0.0.1", "example.com", "*.example.com"],
    "allowed_cidrs": ["127.0.0.0/8", "192.168.1.0/24", "10.0.0.0/8"],
    "allowed_paths": ["./logs", "./artifacts", "./sample_data", "./runs"]
  },
  "execution_limits": {
    "timeout_seconds": 30,
    "max_output_chars": 4000
  },
  "human_in_the_loop": {
    "sensitive_tools": ["inspect_tls_cert", "network_recon_mock__check_host_reachability"]
  }
}
```

### Safety Features
- **Domain & CIDR Allowlist**: Intercepts URLs and hostnames in tool arguments. Rejects out-of-scope targets with `ScopeViolationError`.
- **Path Traversal Protection**: Ensures file paths stay within authorized directory prefixes. Blocks attempts to access `../../etc/shadow` or `C:\Windows`.
- **Human-in-the-Loop (HITL)**: Any tool marked `"requires_approval": true` or listed under `sensitive_tools` prompts the operator:
  ```
  =================================================================
    ⚠️  HUMAN-IN-THE-LOOP (HITL) OPERATOR APPROVAL REQUIRED
  =================================================================
    Tool Name : inspect_tls_cert
    Server    : security_inspector
    Arguments : { "hostname": "example.com" }
  =================================================================
    Proceed with execution? [y/N]:
  ```
- **Context Window Protection**: Automatically truncates tool output exceeding `max_output_chars` before injecting into the LLM context, appending a reference to the untruncated artifact in the Evidence Store.
- **Execution Timeouts**: Enforces timeouts via `asyncio.wait_for` so hung servers do not freeze the host.

---

## Evidence Store & Grounded Report Generator (`core/reporter.py`)

Every tool call produces structured audit evidence:
1. **SQLite Database** (`runs/evidence.db`):
   - `sessions`: Session ID, start time, active model, scope, status, summary.
   - `tool_invocations`: Timestamp, tool name, server name, arguments, status (`SUCCESS`, `TIMEOUT`, `REJECTED_SCOPE`, `REJECTED_HITL`), duration in ms, artifact file path.
   - `findings`: Finding ID (e.g. `HDR-001`, `LOG-001`), severity, title, target, evidence reference, remediation.
2. **Filesystem Artifacts** (`runs/<session_id>/artifacts/`):
   - Untruncated raw JSON output preserved for audit compliance.
3. **Automated Reports**:
   - `runs/<session_id>/report.md`: Clean Markdown documentation.
   - `runs/<session_id>/report.html`: Interactive, styled HTML report with severity badges, metrics cards, and finding tables.

---

## Sample Safe Reference MCP Server (`servers/sample_inspector_mcp.py`)

A pure Python reference server demonstrating the exact stdio JSON-RPC 2.0 contract:

| Tool Name | Parameters | Description |
| :--- | :--- | :--- |
| `check_security_headers` | `target_url`, `timeout` | Inspects HTTP response headers for CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and information disclosure banners. |
| `analyze_audit_log` | `log_path`, `keywords` | Read-only analyzer searching local log files for 403 spikes, failed login attempts, account lockouts, and error severity patterns. |
| `inspect_tls_cert` | `hostname`, `port` | Inspects TLS certificate expiration, validity, issuer, SANs, and protocol version. |
| `check_host_reachability` | `target`, `port` | Socket latency & connectivity verification (available when launched with `--mode recon`). |

---

## Slash Commands Reference

| Command | Action |
| :--- | :--- |
| `/model <name>` | Switch active model on the fly without restarting MCP servers |
| `/models` | Display all configured models and their providers |
| `/servers` | List all MCP servers and their current status |
| `/server enable <name>` | Dynamically plug in an MCP server at runtime |
| `/server disable <name>` | Dynamically unplug an MCP server at runtime |
| `/tools` | List all discovered tools across connected servers |
| `/policy` | Show active target allowlists and safety gates |
| `/report` | Compile Markdown and HTML reports for current session |
| `/clear` | Clear conversation history for a fresh assessment turn |
| `/help` | Display command help menu |
| `/exit`, `/quit` | Terminate host cleanly |

---

## Running Tests

Execute the comprehensive test suite:

```bash
pytest -v
```

All 15 integration and unit tests cover:
- Dynamic model swapping without dropping MCP connections
- Stdio MCP server lifecycle, handshake, and tool discovery
- Plug-and-play dynamic server enabling/disabling
- Policy scope checking (domains, CIDRs, file path traversal)
- Human-in-the-Loop operator approvals and callback rejections
- Context window output truncation
- SQLite evidence store logging & artifact persistence
- Grounded Markdown & HTML report compilation
- End-to-end multi-turn agent reasoning loop
