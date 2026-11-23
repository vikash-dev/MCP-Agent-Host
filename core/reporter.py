"""
Grounded Report Generator
-------------------------
Compiles session evidence, tool execution logs, and structured findings
into comprehensive Markdown and styled HTML security assessment reports.
Sections:
  1. Executive Summary
  2. Scope & Assessment Overview
  3. Findings Table & Vulnerability Breakdown
  4. Evidence References & Raw Tool Artifacts
  5. Actionable Remediation Roadmap
"""

import os
import json
import datetime
from typing import Any, Dict, List, Optional
from core.evidence_store import EvidenceStore


class ReportGenerator:
    """Generates grounded assessment reports from the Evidence Store."""

    def __init__(self, evidence_store: EvidenceStore):
        self.evidence_store = evidence_store

    def generate_markdown_report(self, session_id: str) -> str:
        """Generates a complete Markdown report for the given session."""
        session = self.evidence_store.get_session(session_id) or {
            "session_id": session_id,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "model_name": "unknown",
            "target_scope": []
        }
        invocations = self.evidence_store.get_session_invocations(session_id)
        findings = self.evidence_store.get_session_findings(session_id)

        # Count findings by severity
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
        for f in findings:
            s = f.get("severity", "INFORMATIONAL").upper()
            sev_counts[s] = sev_counts.get(s, 0) + 1

        md_lines = []
        md_lines.append(f"# Automated Security Assessment Report")
        md_lines.append(f"**Session ID:** `{session_id}`  ")
        md_lines.append(f"**Generated:** {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  ")
        md_lines.append(f"**Active Model:** `{session.get('model_name')}`  ")
        md_lines.append(f"**Assessment Status:** `{session.get('status', 'COMPLETED')}`\n")
        md_lines.append("---\n")

        # 1. Executive Summary
        md_lines.append("## 1. Executive Summary")
        total_findings = len(findings)
        overall_risk = "CRITICAL" if sev_counts["CRITICAL"] > 0 else (
            "HIGH" if sev_counts["HIGH"] > 0 else (
                "MEDIUM" if sev_counts["MEDIUM"] > 0 else ("LOW" if sev_counts["LOW"] > 0 else "INFORMATIONAL")
            )
        )
        md_lines.append(
            f"An automated defensive assessment was performed utilizing modular MCP tooling governed by host safety policies. "
            f"During this session, **{len(invocations)}** tool invocations were executed across authorized targets. "
            f"A total of **{total_findings}** finding(s) were identified with an overall risk rating of **{overall_risk}**.\n"
        )
        md_lines.append("### Risk Breakdown")
        md_lines.append("| Severity | Count |")
        md_lines.append("| :--- | :--- |")
        md_lines.append(f"| 🔴 Critical | {sev_counts['CRITICAL']} |")
        md_lines.append(f"| 🟠 High | {sev_counts['HIGH']} |")
        md_lines.append(f"| 🟡 Medium | {sev_counts['MEDIUM']} |")
        md_lines.append(f"| 🟢 Low | {sev_counts['LOW']} |")
        md_lines.append(f"| ℹ️ Informational | {sev_counts['INFORMATIONAL']} |\n")

        # 2. Scope & Assessment Details
        md_lines.append("## 2. Assessment Scope & Guardrail Policy")
        scope = session.get("target_scope", [])
        if scope:
            md_lines.append("Authorized Target Scope Allowlist:")
            for s in scope:
                md_lines.append(f"- `{s}`")
        else:
            md_lines.append("Authorized Target Scope: Configured per `config/policy.json` allowlist rules.")
        md_lines.append(f"\n- **Execution Safety Gates:** Active (Timeout limit, context truncation, HITL approvals)")
        md_lines.append(f"- **Evidence Storage:** SQLite database + raw artifacts in `runs/{session_id}/artifacts/`\n")

        # 3. Findings Table
        md_lines.append("## 3. Discovered Findings")
        if not findings:
            md_lines.append("No security vulnerabilities or policy warnings were discovered in this session.\n")
        else:
            md_lines.append("| Finding ID | Severity | Target | Title | Evidence Ref |")
            md_lines.append("| :--- | :--- | :--- | :--- | :--- |")
            for f in findings:
                sev_emoji = {
                    "CRITICAL": "🔴 Critical",
                    "HIGH": "🟠 High",
                    "MEDIUM": "🟡 Medium",
                    "LOW": "🟢 Low",
                    "INFORMATIONAL": "ℹ️ Info"
                }.get(f.get("severity", "INFORMATIONAL"), f.get("severity"))
                md_lines.append(
                    f"| `{f.get('finding_id')}` | {sev_emoji} | `{f.get('target')}` | {f.get('title')} | `{f.get('evidence_ref')}` |"
                )
            md_lines.append("")

            md_lines.append("### Detailed Findings Breakdown")
            for idx, f in enumerate(findings, start=1):
                md_lines.append(f"#### 3.{idx} [{f.get('severity')}] {f.get('finding_id')}: {f.get('title')}")
                md_lines.append(f"- **Target Asset:** `{f.get('target')}`")
                md_lines.append(f"- **Description:** {f.get('description')}")
                md_lines.append(f"- **Evidence Artifact:** `{f.get('evidence_ref')}`")
                md_lines.append(f"- **Recommended Remediation:** {f.get('remediation')}\n")

        # 4. Evidence References & Raw Tool Invocations
        md_lines.append("## 4. Evidence Audit Trail & Tool Invocations")
        if not invocations:
            md_lines.append("No tools were invoked during this session.\n")
        else:
            md_lines.append("| # | Timestamp | Server | Tool Name | Status | Execution Time | Artifact File |")
            md_lines.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
            for inv in invocations:
                art_name = os.path.basename(inv.get("raw_output_path") or "none")
                md_lines.append(
                    f"| {inv.get('id')} | {inv.get('timestamp')} | `{inv.get('server_name')}` | `{inv.get('tool_name')}` | "
                    f"`{inv.get('status')}` | {inv.get('execution_time_ms', 0):.1f}ms | `{art_name}` |"
                )
            md_lines.append("")

        # 5. Actionable Remediation Roadmap
        md_lines.append("## 5. Prioritized Remediation Roadmap")
        md_lines.append("Based on the evidence gathered, the following defensive actions are recommended:\n")
        md_lines.append("1. **Immediate (0-48 hours):**")
        md_lines.append("   - Review any high-severity authentication failures and enforce IP-based rate limiting or lockout.")
        md_lines.append("   - Renew or reconfigure any expiring or invalid TLS certificates.")
        md_lines.append("2. **Short-Term (1-2 weeks):**")
        md_lines.append("   - Implement standard defensive HTTP headers: `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, and `X-Frame-Options: DENY`.")
        md_lines.append("   - Suppress server banner information disclosure headers (`Server`, `X-Powered-By`).")
        md_lines.append("3. **Long-Term:**")
        md_lines.append("   - Integrate continuous automated MCP-based inspection into CI/CD deployment pipelines.")
        md_lines.append("   - Establish centralized SIEM log collection with automated anomaly alerting.\n")

        md_content = "\n".join(md_lines)

        # Save Markdown file
        out_path = os.path.join(self.evidence_store.runs_dir, session_id, "report.md")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(md_content)

        return out_path

    def generate_html_report(self, session_id: str) -> str:
        """Generates a styled, standalone HTML report for the given session."""
        session = self.evidence_store.get_session(session_id) or {
            "session_id": session_id,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "model_name": "unknown",
            "target_scope": []
        }
        invocations = self.evidence_store.get_session_invocations(session_id)
        findings = self.evidence_store.get_session_findings(session_id)

        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
        for f in findings:
            s = f.get("severity", "INFORMATIONAL").upper()
            sev_counts[s] = sev_counts.get(s, 0) + 1

        overall_risk = "CRITICAL" if sev_counts["CRITICAL"] > 0 else (
            "HIGH" if sev_counts["HIGH"] > 0 else (
                "MEDIUM" if sev_counts["MEDIUM"] > 0 else ("LOW" if sev_counts["LOW"] > 0 else "INFORMATIONAL")
            )
        )

        # Build Findings HTML table rows
        findings_rows = []
        for f in findings:
            sev = f.get("severity", "INFORMATIONAL").upper()
            badge_class = f"badge-{sev.lower()}"
            findings_rows.append(f"""
                <tr>
                    <td><code>{f.get('finding_id')}</code></td>
                    <td><span class="badge {badge_class}">{sev}</span></td>
                    <td><code>{f.get('target')}</code></td>
                    <td><strong>{f.get('title')}</strong><br><small style="color:#64748b;">{f.get('description')}</small></td>
                    <td><code>{f.get('evidence_ref')}</code></td>
                    <td><span style="color:#0f766e;">{f.get('remediation')}</span></td>
                </tr>
            """)

        # Build Invocations HTML table rows
        inv_rows = []
        for inv in invocations:
            art_name = os.path.basename(inv.get("raw_output_path") or "none")
            status = inv.get("status", "SUCCESS")
            status_color = "#16a34a" if status == "SUCCESS" else "#dc2626"
            inv_rows.append(f"""
                <tr>
                    <td>{inv.get('id')}</td>
                    <td>{inv.get('timestamp')}</td>
                    <td><code>{inv.get('server_name')}</code></td>
                    <td><code>{inv.get('tool_name')}</code></td>
                    <td><strong style="color:{status_color};">{status}</strong></td>
                    <td>{inv.get('execution_time_ms', 0):.1f} ms</td>
                    <td><a href="artifacts/{art_name}" target="_blank" style="color:#2563eb;">{art_name}</a></td>
                </tr>
            """)

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Assessment Report - {session_id}</title>
    <style>
        :root {{
            --bg-main: #f8fafc;
            --bg-card: #ffffff;
            --text-main: #0f172a;
            --text-muted: #64748b;
            --primary: #0284c7;
            --border: #e2e8f0;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #10b981;
            --info: #64748b;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-main);
            color: var(--text-main);
            line-height: 1.6;
            margin: 0;
            padding: 30px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header-card {{
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #ffffff;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.08);
            margin-bottom: 25px;
        }}
        .header-card h1 {{ margin: 0 0 10px 0; font-size: 26px; }}
        .header-meta {{ display: flex; flex-wrap: wrap; gap: 20px; font-size: 14px; opacity: 0.9; margin-top: 15px; }}
        .card {{
            background: var(--bg-card);
            padding: 25px;
            border-radius: 10px;
            border: 1px solid var(--border);
            margin-bottom: 25px;
            box-shadow: 0 2px 6px rgba(0,0,0,0.03);
        }}
        .card h2 {{
            margin-top: 0;
            font-size: 20px;
            border-bottom: 2px solid #f1f5f9;
            padding-bottom: 10px;
            color: #1e293b;
        }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }}
        .metric-box {{
            padding: 15px;
            border-radius: 8px;
            text-align: center;
            border: 1px solid var(--border);
        }}
        .metric-box .number {{ font-size: 28px; font-weight: bold; margin-bottom: 4px; }}
        .metric-box .label {{ font-size: 13px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            font-size: 11px;
            font-weight: 700;
            border-radius: 4px;
            text-transform: uppercase;
        }}
        .badge-critical {{ background: #fee2e2; color: #991b1b; }}
        .badge-high {{ background: #ffedd5; color: #9a3412; }}
        .badge-medium {{ background: #fef9c3; color: #854d0e; }}
        .badge-low {{ background: #dcfce7; color: #166534; }}
        .badge-informational {{ background: #f1f5f9; color: #475569; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            font-size: 14px;
        }}
        th, td {{
            text-align: left;
            padding: 12px 14px;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            background-color: #f8fafc;
            color: #475569;
            font-weight: 600;
        }}
        tr:hover {{ background-color: #f8fafc; }}
        code {{
            background: #f1f5f9;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 13px;
            font-family: Consolas, "Courier New", monospace;
        }}
        .remediation-step {{
            margin-bottom: 15px;
            padding-left: 15px;
            border-left: 3px solid var(--primary);
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header-card">
            <h1>Defensive Security Assessment Report</h1>
            <p style="margin: 0; opacity: 0.85;">Modular MCP Agent Host Automated Audit</p>
            <div class="header-meta">
                <div><strong>Session ID:</strong> {session_id}</div>
                <div><strong>Active LLM:</strong> {session.get('model_name')}</div>
                <div><strong>Generated:</strong> {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</div>
                <div><strong>Overall Posture:</strong> <span class="badge badge-{overall_risk.lower()}">{overall_risk}</span></div>
            </div>
        </div>

        <!-- Executive Summary -->
        <div class="card">
            <h2>1. Executive Summary</h2>
            <p>
                An automated security assessment was executed under the host safety policy.
                A total of <strong>{len(invocations)}</strong> tool execution cycles were recorded in the Evidence Store.
                The assessment discovered <strong>{len(findings)}</strong> security finding(s).
            </p>
            <div class="metrics-grid">
                <div class="metric-box" style="background:#fef2f2; border-color:#fca5a5;">
                    <div class="number" style="color:#b91c1c;">{sev_counts['CRITICAL']}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="metric-box" style="background:#fff7ed; border-color:#fdba74;">
                    <div class="number" style="color:#c2410c;">{sev_counts['HIGH']}</div>
                    <div class="label">High</div>
                </div>
                <div class="metric-box" style="background:#fefce8; border-color:#fde047;">
                    <div class="number" style="color:#a16207;">{sev_counts['MEDIUM']}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="metric-box" style="background:#f0fdf4; border-color:#86efac;">
                    <div class="number" style="color:#15803d;">{sev_counts['LOW']}</div>
                    <div class="label">Low</div>
                </div>
                <div class="metric-box" style="background:#f8fafc; border-color:#cbd5e1;">
                    <div class="number" style="color:#475569;">{len(invocations)}</div>
                    <div class="label">Tool Invocations</div>
                </div>
            </div>
        </div>

        <!-- Scope & Guardrails -->
        <div class="card">
            <h2>2. Target Scope & Guardrails Policy</h2>
            <p><strong>Safety Governance:</strong> Enforced via central <code>config/policy.json</code>.</p>
            <ul>
                <li><strong>Target Allowlists:</strong> Domain allowlist, CIDR block validation, and path traversal boundary checks.</li>
                <li><strong>Execution Timeouts:</strong> Configured tool execution limits with graceful abort.</li>
                <li><strong>Output Truncation:</strong> LLM prompt context window overflow protection.</li>
                <li><strong>Human-in-the-Loop (HITL):</strong> Explicit operator confirmation gates for sensitive inspection operations.</li>
            </ul>
        </div>

        <!-- Findings Table -->
        <div class="card">
            <h2>3. Discovered Findings</h2>
            {'<table><thead><tr><th>ID</th><th>Severity</th><th>Target</th><th>Finding</th><th>Evidence Ref</th><th>Remediation</th></tr></thead><tbody>' + "".join(findings_rows) + '</tbody></table>' if findings else '<p>No security findings or violations were detected during this session.</p>'}
        </div>

        <!-- Evidence Audit Trail -->
        <div class="card">
            <h2>4. Evidence Audit Trail & Tool Invocations</h2>
            {'<table><thead><tr><th>#</th><th>Timestamp</th><th>Server</th><th>Tool</th><th>Status</th><th>Duration</th><th>Artifact</th></tr></thead><tbody>' + "".join(inv_rows) + '</tbody></table>' if invocations else '<p>No tool invocations recorded.</p>'}
        </div>

        <!-- Remediation Roadmap -->
        <div class="card">
            <h2>5. Actionable Remediation Roadmap</h2>
            <div class="remediation-step">
                <strong>Phase 1: Immediate Actions (0 - 48 Hours)</strong>
                <p>Enforce strict lockout thresholds on repeated authentication failures detected in audit logs. Renew any expiring SSL/TLS certificates.</p>
            </div>
            <div class="remediation-step">
                <strong>Phase 2: Tactical Hardening (1 - 2 Weeks)</strong>
                <p>Deploy standard defensive headers: <code>Content-Security-Policy</code>, <code>Strict-Transport-Security</code>, and <code>X-Content-Type-Options: nosniff</code>. Remove server version disclosure banners.</p>
            </div>
            <div class="remediation-step">
                <strong>Phase 3: Continuous Assurance (Ongoing)</strong>
                <p>Incorporate automated MCP-driven security scans into continuous delivery pipelines with SQLite evidence auditing.</p>
            </div>
        </div>
    </div>
</body>
</html>
        """

        out_path = os.path.join(self.evidence_store.runs_dir, session_id, "report.html")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(html_template)

        return out_path

    def compile_reports(self, session_id: str) -> Dict[str, str]:
        """Compiles both Markdown and HTML reports and returns their absolute filepaths."""
        md_path = self.generate_markdown_report(session_id)
        html_path = self.generate_html_report(session_id)
        return {
            "markdown": md_path,
            "html": html_path
        }
