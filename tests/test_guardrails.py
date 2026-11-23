"""
Tests for Policy, Scope & Human-in-the-Loop (HITL) Guardrails Middleware.
"""

import os
import pytest
from core.guardrails import (
    GuardrailsMiddleware,
    ScopeViolationError,
    HITLRejectionError
)


@pytest.fixture
def guardrails(tmp_path):
    policy_content = """
    {
      "scope": {
        "allowed_domains": ["example.com", "*.internal.corp", "localhost", "127.0.0.1"],
        "allowed_cidrs": ["10.0.0.0/8", "192.168.1.0/24"],
        "allowed_paths": ["./logs", "./sample_data", "./runs"]
      },
      "execution_limits": {
        "timeout_seconds": 15,
        "max_output_chars": 500
      },
      "human_in_the_loop": {
        "default_requires_approval": false,
        "sensitive_tools": ["inspect_tls_cert", "dangerous_tool"]
      }
    }
    """
    policy_file = tmp_path / "test_policy.json"
    policy_file.write_text(policy_content, encoding="utf-8")
    return GuardrailsMiddleware(policy_path=str(policy_file), auto_approve=False)


def test_domain_allowlist_valid(guardrails):
    # Allowed domains
    assert guardrails.is_domain_allowed("example.com")
    assert guardrails.is_domain_allowed("sub.internal.corp")
    assert guardrails.is_domain_allowed("localhost")
    assert guardrails.is_domain_allowed("127.0.0.1")

    # Arguments with valid URLs should pass
    guardrails.validate_scope("check_security_headers", {"target_url": "https://example.com/api"})
    guardrails.validate_scope("check_security_headers", {"target_url": "http://app.internal.corp:8080/health"})


def test_domain_allowlist_violation(guardrails):
    assert not guardrails.is_domain_allowed("malicious-site.com")
    assert not guardrails.is_domain_allowed("unauthorized.com")

    with pytest.raises(ScopeViolationError) as exc_info:
        guardrails.validate_scope("check_security_headers", {"target_url": "https://unauthorized.com/login"})
    assert "not in the authorized scope allowlist" in str(exc_info.value).lower()


def test_cidr_ip_allowlist(guardrails):
    assert guardrails.is_ip_allowed("10.1.2.3")
    assert guardrails.is_ip_allowed("192.168.1.50")
    assert not guardrails.is_ip_allowed("8.8.8.8")
    assert not guardrails.is_ip_allowed("172.16.0.1")

    guardrails.validate_scope("inspect_target", {"hostname": "10.0.0.5"})

    with pytest.raises(ScopeViolationError):
        guardrails.validate_scope("inspect_target", {"hostname": "8.8.8.8"})


def test_path_allowlist_and_traversal(guardrails):
    # Valid relative paths
    assert guardrails.is_path_allowed("./sample_data/audit_sample.log")
    assert guardrails.is_path_allowed("logs/app.log")

    guardrails.validate_scope("analyze_audit_log", {"log_path": "./sample_data/audit_sample.log"})

    # Path traversal outside allowed paths must raise ScopeViolationError
    with pytest.raises(ScopeViolationError):
        guardrails.validate_scope("analyze_audit_log", {"log_path": "../../etc/shadow"})

    with pytest.raises(ScopeViolationError):
        guardrails.validate_scope("analyze_audit_log", {"log_path": "C:\\Windows\\System32\\cmd.exe"})


def test_hitl_approval_callback(guardrails):
    # Non-sensitive tool should not require HITL
    server_cfg = {"name": "test_server", "requires_approval": False, "tools_require_approval": []}
    guardrails.check_hitl_approval("check_security_headers", {"target_url": "https://example.com"}, server_cfg)

    # Sensitive tool without approval must raise error
    with pytest.raises(HITLRejectionError):
        # Without callback and non-interactive input, it fails safely
        guardrails.check_hitl_approval("inspect_tls_cert", {"hostname": "example.com"}, server_cfg)

    # With approval callback returning True
    guardrails.hitl_callback = lambda tool, args: True
    guardrails.check_hitl_approval("inspect_tls_cert", {"hostname": "example.com"}, server_cfg)

    # With approval callback returning False
    guardrails.hitl_callback = lambda tool, args: False
    with pytest.raises(HITLRejectionError):
        guardrails.check_hitl_approval("inspect_tls_cert", {"hostname": "example.com"}, server_cfg)


def test_output_truncation(guardrails):
    short_text = "Status: OK"
    out, truncated = guardrails.truncate_output(short_text, artifact_path="test_art.json")
    assert not truncated
    assert out == short_text

    long_text = "A" * 1000
    out, truncated = guardrails.truncate_output(long_text, artifact_path="test_art.json")
    assert truncated
    assert len(out) <= 600
    assert "TRUNCATED" in out
    assert "test_art.json" in out
