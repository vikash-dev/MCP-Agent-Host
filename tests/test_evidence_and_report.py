"""
Tests for Evidence Store & Grounded Report Generator.
"""

import os
import json
import sqlite3
import pytest
from core.evidence_store import EvidenceStore
from core.reporter import ReportGenerator


@pytest.fixture
def evidence_setup(tmp_path):
    db_path = tmp_path / "test_evidence.db"
    runs_dir = tmp_path / "runs"
    store = EvidenceStore(db_path=str(db_path), runs_dir=str(runs_dir))
    reporter = ReportGenerator(store)
    return store, reporter, str(runs_dir)


def test_evidence_session_lifecycle(evidence_setup):
    store, reporter, runs_dir = evidence_setup
    session_id = "test_sess_001"

    # Start session
    info = store.start_session(session_id, model_name="mock/security-agent", target_scope=["example.com"])
    assert info["session_id"] == session_id
    assert os.path.isdir(info["artifacts_dir"])

    # Retrieve session
    session = store.get_session(session_id)
    assert session is not None
    assert session["model_name"] == "mock/security-agent"
    assert "example.com" in session["target_scope"]

    # Log tool invocation
    inv_data = {
        "status_code": 200,
        "missing_security_headers": ["Content-Security-Policy", "X-Frame-Options"],
        "findings": [
            {
                "header": "Content-Security-Policy",
                "severity": "HIGH",
                "issue": "Missing CSP",
                "recommendation": "Configure standard CSP"
            }
        ]
    }
    inv = store.log_tool_invocation(
        session_id=session_id,
        server_name="security_inspector",
        tool_name="check_security_headers",
        arguments={"target_url": "https://example.com"},
        raw_output=inv_data,
        status="SUCCESS",
        execution_time_ms=45.2
    )

    assert inv["status"] == "SUCCESS"
    assert os.path.exists(inv["artifact_path"])

    # Verify invocation recorded in SQLite
    invs = store.get_session_invocations(session_id)
    assert len(invs) == 1
    assert invs[0]["tool_name"] == "check_security_headers"
    assert invs[0]["server_name"] == "security_inspector"

    # Verify auto-extracted finding
    findings = store.get_session_findings(session_id)
    assert len(findings) >= 1
    assert findings[0]["severity"] == "HIGH"
    assert "CSP" in findings[0]["title"]


def test_report_generation(evidence_setup):
    store, reporter, runs_dir = evidence_setup
    session_id = "test_sess_report"
    store.start_session(session_id, model_name="mock/security-agent", target_scope=["example.com"])

    store.log_tool_invocation(
        session_id=session_id,
        server_name="security_inspector",
        tool_name="analyze_audit_log",
        arguments={"log_path": "./sample_data/audit_sample.log"},
        raw_output={
            "matched_events_count": 5,
            "suspicious_patterns_detected": [
                {
                    "pattern": "Repeated Failed Logins",
                    "severity": "HIGH",
                    "details": "Multiple auth failures observed."
                }
            ]
        },
        status="SUCCESS",
        execution_time_ms=30.0
    )

    reports = reporter.compile_reports(session_id)
    md_path = reports["markdown"]
    html_path = reports["html"]

    assert os.path.exists(md_path)
    assert os.path.exists(html_path)

    # Verify Markdown contents
    with open(md_path, "r", encoding="utf-8") as f:
        md_text = f.read()
    assert "## 1. Executive Summary" in md_text
    assert "## 2. Assessment Scope & Guardrail Policy" in md_text
    assert "## 3. Discovered Findings" in md_text
    assert "## 4. Evidence Audit Trail & Tool Invocations" in md_text
    assert "## 5. Prioritized Remediation Roadmap" in md_text
    assert "Repeated Failed Logins" in md_text

    # Verify HTML contents
    with open(html_path, "r", encoding="utf-8") as f:
        html_text = f.read()
    assert "<!DOCTYPE html>" in html_text
    assert "badge badge-high" in html_text
    assert "Repeated Failed Logins" in html_text
