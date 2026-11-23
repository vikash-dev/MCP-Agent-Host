"""
Tests for Dynamic LLM Provider & Model Switcher.
"""

import os
import json
import pytest
from core.llm_provider import ModelSwitcher, MockSecurityAgentClient, OllamaClient, OpenAICompatibleClient


@pytest.fixture
def models_config(tmp_path):
    config_content = """
    {
      "active_model": "mock/security-agent",
      "providers": {
        "mock": {
          "type": "mock",
          "description": "Mock provider"
        },
        "ollama": {
          "type": "ollama",
          "base_url": "http://localhost:11434/v1",
          "description": "Local Ollama"
        },
        "openai": {
          "type": "openai",
          "base_url": "https://api.openai.com/v1",
          "api_key": "test-key",
          "description": "OpenAI"
        }
      },
      "models": {
        "mock/security-agent": {
          "provider": "mock",
          "model_name": "mock-security-agent",
          "description": "Deterministic mock agent"
        },
        "ollama/qwen2.5:7b": {
          "provider": "ollama",
          "model_name": "qwen2.5:7b",
          "description": "Qwen 2.5 7B"
        },
        "ollama/mistral:7b": {
          "provider": "ollama",
          "model_name": "mistral:7b",
          "description": "Mistral 7B"
        },
        "openai/gpt-4o": {
          "provider": "openai",
          "model_name": "gpt-4o",
          "description": "GPT-4o"
        }
      }
    }
    """
    cfg_file = tmp_path / "models.json"
    cfg_file.write_text(config_content, encoding="utf-8")
    return str(cfg_file)


def test_model_switcher_initialization(models_config):
    switcher = ModelSwitcher(config_path=models_config)
    assert switcher.active_model_name == "mock/security-agent"
    assert isinstance(switcher.get_client(), MockSecurityAgentClient)

    models = switcher.list_models()
    assert len(models) == 4
    active_keys = [m["key"] for m in models if m["is_active"]]
    assert active_keys == ["mock/security-agent"]


def test_dynamic_model_switching(models_config):
    switcher = ModelSwitcher(config_path=models_config)

    # 1. Switch to Ollama model
    res = switcher.switch_model("ollama/qwen2.5:7b")
    assert "Successfully switched" in res
    assert switcher.active_model_name == "ollama/qwen2.5:7b"
    assert isinstance(switcher.get_client(), OllamaClient)

    # 2. Switch to OpenAI model
    switcher.switch_model("openai/gpt-4o")
    assert switcher.active_model_name == "openai/gpt-4o"
    assert isinstance(switcher.get_client(), OpenAICompatibleClient)

    # 3. Switch back to Mock
    switcher.switch_model("mock/security-agent")
    assert switcher.active_model_name == "mock/security-agent"
    assert isinstance(switcher.get_client(), MockSecurityAgentClient)


def test_switch_to_invalid_model(models_config):
    switcher = ModelSwitcher(config_path=models_config)
    with pytest.raises(ValueError) as exc:
        switcher.switch_model("nonexistent/invalid-model")
    assert "not registered" in str(exc.value)


@pytest.mark.asyncio
async def test_mock_agent_tool_calling():
    mock_client = MockSecurityAgentClient(
        model_name="mock/security-agent",
        config={"model_name": "mock-security-agent"}
    )

    tools_schemas = [
        {
            "type": "function",
            "function": {
                "name": "check_security_headers",
                "description": "Inspects HTTP headers",
                "parameters": {"type": "object", "properties": {"target_url": {"type": "string"}}}
            }
        }
    ]

    # Turn 1: User asks for headers check -> emits tool call
    messages = [{"role": "user", "content": "Analyze headers for https://example.com"}]
    response = await mock_client.complete(messages=messages, tools=tools_schemas)

    assert len(response.tool_calls) == 1
    assert response.tool_calls[0].name == "check_security_headers"
    assert response.tool_calls[0].arguments["target_url"] == "https://example.com"

    # Turn 2: Providing tool result -> model synthesizes response
    tool_resp = {
        "overall_grade": "B",
        "score_percentage": 80,
        "missing_security_headers": ["Content-Security-Policy"],
        "findings": [{"header": "CSP", "severity": "HIGH", "issue": "Missing CSP"}]
    }
    messages.append({
        "role": "assistant",
        "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "check_security_headers"}}]
    })
    messages.append({
        "role": "tool",
        "tool_call_id": "call_1",
        "name": "check_security_headers",
        "content": json.dumps(tool_resp)
    })

    synthesis = await mock_client.complete(messages=messages, tools=tools_schemas)
    assert len(synthesis.tool_calls) == 0
    assert "Security Assessment Synthesis" in synthesis.content
    assert "Grade `B`" in synthesis.content
