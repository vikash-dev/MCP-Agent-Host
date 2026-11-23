"""
Dynamic LLM Provider & Model Switcher
-------------------------------------
Unified interface for OpenAI-compatible endpoints, local Ollama models
(e.g., qwen2.5, mistral, gemma2), and deterministic offline mock agents.
Supports seamless runtime model switching without restarting MCP server connections.
"""

import os
import re
import json
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
import openai


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: Dict[str, Any]


@dataclass
class LLMResponse:
    content: Optional[str] = None
    tool_calls: List[ToolCall] = field(default_factory=list)
    model: str = ""
    finish_reason: str = "stop"
    usage: Dict[str, Any] = field(default_factory=dict)


class BaseLLMClient(ABC):
    """Abstract interface for all LLM providers."""

    def __init__(self, model_name: str, config: Dict[str, Any]):
        self.model_name = model_name
        self.config = config

    @abstractmethod
    async def complete(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None
    ) -> LLMResponse:
        """Sends messages and tool schemas to the model and returns an LLMResponse."""
        pass


class OpenAICompatibleClient(BaseLLMClient):
    """Client for OpenAI and any OpenAI-compatible server (vLLM, LMStudio, LocalAI)."""

    def __init__(self, model_name: str, config: Dict[str, Any], provider_config: Dict[str, Any]):
        super().__init__(model_name, config)
        self.provider_config = provider_config
        base_url = provider_config.get("base_url", "https://api.openai.com/v1")

        raw_key = provider_config.get("api_key", "")
        # Resolve environment variable syntax if present
        if raw_key.startswith("${") and raw_key.endswith("}"):
            var_expr = raw_key[2:-1]
            if ":-" in var_expr:
                var_name, default_val = var_expr.split(":-", 1)
                api_key = os.environ.get(var_name, default_val)
            else:
                api_key = os.environ.get(var_expr, "none")
        else:
            api_key = raw_key or "none"

        self.client = openai.AsyncOpenAI(
            base_url=base_url,
            api_key=api_key or "none"
        )

    async def complete(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None
    ) -> LLMResponse:
        kwargs: Dict[str, Any] = {
            "model": self.config.get("model_name", self.model_name),
            "messages": messages,
            "temperature": self.config.get("temperature", 0.2),
            "max_tokens": self.config.get("max_tokens", 4096)
        }
        if tools and len(tools) > 0:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        try:
            resp = await self.client.chat.completions.create(**kwargs)
            choice = resp.choices[0]
            msg = choice.message

            tool_calls = []
            if msg.tool_calls:
                for tc in msg.tool_calls:
                    try:
                        args = json.loads(tc.function.arguments)
                    except Exception:
                        args = {"raw_input": tc.function.arguments}
                    tool_calls.append(ToolCall(
                        id=tc.id or f"call_{tc.function.name}",
                        name=tc.function.name,
                        arguments=args
                    ))

            usage_dict = {}
            if resp.usage:
                usage_dict = {
                    "prompt_tokens": resp.usage.prompt_tokens,
                    "completion_tokens": resp.usage.completion_tokens,
                    "total_tokens": resp.usage.total_tokens
                }

            return LLMResponse(
                content=msg.content,
                tool_calls=tool_calls,
                model=resp.model or self.model_name,
                finish_reason=choice.finish_reason or "stop",
                usage=usage_dict
            )
        except Exception as e:
            raise RuntimeError(f"OpenAI completion failed for model '{self.model_name}': {e}")


class OllamaClient(BaseLLMClient):
    """
    Client for local Ollama instances (e.g., qwen2.5:7b, mistral:7b, gemma2:9b).
    Uses Ollama's OpenAI-compatible /v1 endpoint for seamless tool/function calling.
    """

    def __init__(self, model_name: str, config: Dict[str, Any], provider_config: Dict[str, Any]):
        super().__init__(model_name, config)
        self.provider_config = provider_config
        base_url = provider_config.get("base_url", "http://localhost:11434/v1")
        self.client = openai.AsyncOpenAI(
            base_url=base_url,
            api_key="ollama"
        )

    async def complete(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None
    ) -> LLMResponse:
        actual_model = self.config.get("model_name", self.model_name)
        kwargs: Dict[str, Any] = {
            "model": actual_model,
            "messages": messages,
            "temperature": self.config.get("temperature", 0.2),
            "max_tokens": self.config.get("max_tokens", 4096)
        }
        if tools and len(tools) > 0:
            kwargs["tools"] = tools

        try:
            resp = await self.client.chat.completions.create(**kwargs)
            choice = resp.choices[0]
            msg = choice.message

            tool_calls = []
            if msg.tool_calls:
                for tc in msg.tool_calls:
                    try:
                        args = json.loads(tc.function.arguments)
                    except Exception:
                        args = {"raw_input": tc.function.arguments}
                    tool_calls.append(ToolCall(
                        id=tc.id or f"call_{tc.function.name}",
                        name=tc.function.name,
                        arguments=args
                    ))

            usage_dict = {}
            if resp.usage:
                usage_dict = {
                    "prompt_tokens": resp.usage.prompt_tokens,
                    "completion_tokens": resp.usage.completion_tokens,
                    "total_tokens": resp.usage.total_tokens
                }

            return LLMResponse(
                content=msg.content,
                tool_calls=tool_calls,
                model=actual_model,
                finish_reason=choice.finish_reason or "stop",
                usage=usage_dict
            )
        except Exception as e:
            err_str = str(e)
            local_models = []
            try:
                import httpx
                raw_url = self.provider_config.get("base_url", "http://localhost:11434/v1")
                api_base = raw_url.replace("/v1", "").rstrip("/")
                r = httpx.get(f"{api_base}/api/tags", timeout=2.0)
                if r.status_code == 200:
                    local_models = [m.get("name") for m in r.json().get("models", [])]
            except Exception:
                pass

            if "404" in err_str or "not found" in err_str.lower():
                suggestion = ""
                if local_models:
                    family = actual_model.split(":")[0]
                    matches = [m for m in local_models if family in m]
                    best_match = matches[0] if matches else local_models[0]
                    suggestion = (
                        f"\n\nInstalled models in your local Ollama:\n"
                        f"  {', '.join([f'`{m}`' for m in local_models])}\n\n"
                        f"💡 Quick Fix: Switch to an installed model like `{best_match}`:\n"
                        f"  - In Web UI: Click 'Select Model' on `ollama/{best_match}`\n"
                        f"  - In CLI: Type `/model ollama/{best_match}`\n"
                        f"  - Or download `{actual_model}` in terminal: `ollama pull {actual_model}`"
                    )
                else:
                    suggestion = f"\n\nRun `ollama pull {actual_model}` in your terminal to download this model."

                raise ConnectionError(
                    f"Model '{actual_model}' was not found in your local Ollama instance.{suggestion}"
                )

            raise ConnectionError(
                f"Failed to connect to local Ollama instance at {self.provider_config.get('base_url')} for model '{actual_model}'. "
                f"Ensure Ollama is running (`ollama serve`). Error details: {err_str}"
            )


class MockSecurityAgentClient(BaseLLMClient):
    """
    Deterministic Mock Security Agent.
    Enables offline unit testing, end-to-end multi-step tool verification,
    and demonstrations without requiring external API keys or Ollama GPU resources.
    """

    async def complete(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None
    ) -> LLMResponse:
        # Check if the last message contains tool execution results
        tool_results = [m for m in messages if m.get("role") == "tool"]

        if not tool_results:
            # Turn 1: Analyze user request and emit tool call(s)
            user_text = ""
            for m in reversed(messages):
                if m.get("role") == "user":
                    user_text = m.get("content", "")
                    break

            available_tool_names = [t.get("function", {}).get("name") for t in (tools or [])]

            # 1. URL pattern -> check_security_headers
            url_match = re.search(r"https?://[^\s]+", user_text)
            if url_match and "check_security_headers" in available_tool_names:
                target_url = url_match.group(0).rstrip(".,;")
                return LLMResponse(
                    content="Initiating defensive security inspection of target web endpoint headers.",
                    tool_calls=[ToolCall(
                        id="call_mock_headers_001",
                        name="check_security_headers",
                        arguments={"target_url": target_url}
                    )],
                    model=self.model_name,
                    finish_reason="tool_calls"
                )

            # 2. Log path pattern -> analyze_audit_log
            log_match = re.search(r"(?:audit|log|sample_data)[^\s]*\.log", user_text, re.IGNORECASE)
            if (log_match or "log" in user_text.lower()) and "analyze_audit_log" in available_tool_names:
                log_path = log_match.group(0) if log_match else "sample_data/audit_sample.log"
                return LLMResponse(
                    content=f"Examining local security audit log at '{log_path}'.",
                    tool_calls=[ToolCall(
                        id="call_mock_log_002",
                        name="analyze_audit_log",
                        arguments={"log_path": log_path}
                    )],
                    model=self.model_name,
                    finish_reason="tool_calls"
                )

            # 3. TLS / cert pattern -> inspect_tls_cert
            if ("tls" in user_text.lower() or "cert" in user_text.lower()) and "inspect_tls_cert" in available_tool_names:
                domain_match = re.search(r"([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", user_text)
                hostname = domain_match.group(1) if domain_match else "example.com"
                return LLMResponse(
                    content=f"Inspecting SSL/TLS certificate configuration for hostname '{hostname}'.",
                    tool_calls=[ToolCall(
                        id="call_mock_tls_003",
                        name="inspect_tls_cert",
                        arguments={"hostname": hostname}
                    )],
                    model=self.model_name,
                    finish_reason="tool_calls"
                )

            # Default response if no tool pattern detected
            return LLMResponse(
                content=(
                    f"Mock Security Agent ({self.model_name}) ready. "
                    "You can ask me to inspect HTTP security headers for a target URL (e.g. https://example.com), "
                    "analyze audit logs (e.g. sample_data/audit_sample.log), or inspect TLS certificates."
                ),
                tool_calls=[],
                model=self.model_name,
                finish_reason="stop"
            )

        else:
            # Turn 2: Synthesize findings from executed tools
            summary_sections = [
                "### Security Assessment Synthesis",
                f"**Agent Model**: `{self.model_name}`",
                f"**Evidence Gathered**: {len(tool_results)} tool response(s) analyzed."
            ]

            for tr in tool_results:
                tool_content = tr.get("content", "")
                try:
                    parsed = json.loads(tool_content)
                    if "overall_grade" in parsed:
                        grade = parsed.get("overall_grade")
                        score = parsed.get("score_percentage")
                        missing = parsed.get("missing_security_headers", [])
                        summary_sections.append(
                            f"\n- **Header Security Posture**: Grade `{grade}` (Score: {score}%)\n"
                            f"  - **Missing Headers**: {', '.join(missing) if missing else 'None'}\n"
                            f"  - **Identified Findings**: {len(parsed.get('findings', []))} recommendations recorded in Evidence Store."
                        )
                    elif "total_lines_inspected" in parsed:
                        lines = parsed.get("total_lines_inspected")
                        matched = parsed.get("matched_events_count")
                        sev = parsed.get("severity_breakdown", {})
                        summary_sections.append(
                            f"\n- **Audit Log Inspection**: {lines} total lines analyzed, {matched} matched security events.\n"
                            f"  - **Breakdown**: ALERT={sev.get('ALERT', 0)}, ERROR={sev.get('ERROR', 0)}, WARNING={sev.get('WARNING', 0)}\n"
                            f"  - **High-Risk Indicators**: Account lockouts and unauthorized access attempts detected."
                        )
                    elif "is_valid" in parsed:
                        valid = "VALID" if parsed.get("is_valid") else "INVALID/EXPIRED"
                        days = parsed.get("days_remaining", 0)
                        summary_sections.append(
                            f"\n- **TLS Certificate Status**: `{valid}` ({days} days remaining)\n"
                            f"  - **TLS Protocol**: {parsed.get('tls_version')}"
                        )
                except Exception:
                    summary_sections.append(f"\n- **Raw Artifact Output**: {tool_content[:200]}...")

            summary_sections.append("\n**Remediation Recommendation**: Refer to generated session report for detailed remediation roadmaps.")
            return LLMResponse(
                content="\n".join(summary_sections),
                tool_calls=[],
                model=self.model_name,
                finish_reason="stop"
            )


class ModelSwitcher:
    """
    Manages active model state and supports dynamic switching at runtime
    without restarting MCP server connections.
    """

    def __init__(self, config_path: str = "config/models.json"):
        self.config_path = os.path.abspath(config_path)
        self.config_data: Dict[str, Any] = {}
        self.active_model_name: str = ""
        self.active_client: Optional[BaseLLMClient] = None
        self._load_config()

    def _load_config(self) -> None:
        """Loads models configuration registry."""
        if not os.path.exists(self.config_path):
            raise FileNotFoundError(f"Configuration file not found: {self.config_path}")

        with open(self.config_path, "r", encoding="utf-8") as f:
            self.config_data = json.load(f)

        self.active_model_name = self.config_data.get("active_model", "mock/security-agent")
        self._instantiate_client(self.active_model_name)

    def _instantiate_client(self, model_key: str) -> BaseLLMClient:
        """Instantiates the client corresponding to a model key."""
        models = self.config_data.get("models", {})
        if model_key not in models:
            # Check for partial match or provider fallback
            matching = [k for k in models.keys() if model_key.lower() in k.lower()]
            if matching:
                model_key = matching[0]
            else:
                raise ValueError(
                    f"Model '{model_key}' is not registered in config/models.json. "
                    f"Available models: {list(models.keys())}"
                )

        model_cfg = models[model_key]
        provider_name = model_cfg.get("provider", "mock")
        providers = self.config_data.get("providers", {})
        provider_cfg = providers.get(provider_name, {})

        if provider_name == "ollama":
            client = OllamaClient(model_name=model_key, config=model_cfg, provider_config=provider_cfg)
        elif provider_name in ["openai", "custom_openai", "openai_compatible"]:
            client = OpenAICompatibleClient(model_name=model_key, config=model_cfg, provider_config=provider_cfg)
        elif provider_name == "mock":
            client = MockSecurityAgentClient(model_name=model_key, config=model_cfg)
        else:
            raise ValueError(f"Unknown LLM provider type '{provider_name}' for model '{model_key}'")

        self.active_model_name = model_key
        self.active_client = client
        return client

    def switch_model(self, model_name: str) -> str:
        """
        Dynamically switches the active model at runtime.
        Crucially: does NOT touch, restart, or disconnect active MCP server processes.
        """
        self._instantiate_client(model_name)
        # Persist active_model selection to config
        self.config_data["active_model"] = self.active_model_name
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(self.config_data, f, indent=2)

        return f"Successfully switched active LLM to '{self.active_model_name}' (MCP connections preserved)."

    def list_models(self) -> List[Dict[str, Any]]:
        """Returns all configured models with metadata and active state."""
        models = self.config_data.get("models", {})
        out = []
        for key, cfg in models.items():
            out.append({
                "key": key,
                "provider": cfg.get("provider"),
                "model_name": cfg.get("model_name"),
                "is_active": (key == self.active_model_name),
                "description": cfg.get("description", "")
            })
        return out

    def sync_installed_ollama_models(self) -> List[Dict[str, Any]]:
        """
        Queries the local Ollama instance (/api/tags) and automatically
        registers any discovered models into config/models.json.
        """
        import httpx
        ollama_cfg = self.config_data.get("providers", {}).get("ollama", {})
        raw_url = ollama_cfg.get("base_url", "http://localhost:11434/v1")
        api_base = raw_url.replace("/v1", "").rstrip("/")

        try:
            resp = httpx.get(f"{api_base}/api/tags", timeout=3.0)
            if resp.status_code == 200:
                raw_models = resp.json().get("models", [])
                for rm in raw_models:
                    m_name = rm.get("name")
                    if not m_name:
                        continue
                    m_key = f"ollama/{m_name}"
                    if m_key not in self.config_data["models"]:
                        self.config_data["models"][m_key] = {
                            "provider": "ollama",
                            "model_name": m_name,
                            "temperature": 0.2,
                            "max_tokens": 4096,
                            "context_window": 32768,
                            "description": f"Auto-detected local Ollama model: {m_name}"
                        }

                with open(self.config_path, "w", encoding="utf-8") as f:
                    json.dump(self.config_data, f, indent=2)

        except Exception as e:
            sys.stderr.write(f"[ModelSwitcher] Could not query Ollama tags: {e}\n")

        return self.list_models()

    def get_client(self) -> BaseLLMClient:
        if not self.active_client:
            self._instantiate_client(self.active_model_name)
        return self.active_client
