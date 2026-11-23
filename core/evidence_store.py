"""
Evidence Store
--------------
Manages structured persistence of assessment sessions, tool invocations,
untruncated raw artifacts, and findings using SQLite and filesystem artifacts.
"""

import os
import json
import sqlite3
import datetime
from typing import Any, Dict, List, Optional


class EvidenceStore:
    def __init__(self, db_path: str = "runs/evidence.db", runs_dir: str = "runs"):
        self.db_path = os.path.abspath(db_path)
        self.runs_dir = os.path.abspath(runs_dir)
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        os.makedirs(self.runs_dir, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Initializes the SQLite schema."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    model_name TEXT NOT NULL,
                    target_scope TEXT,
                    status TEXT DEFAULT 'IN_PROGRESS',
                    summary TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tool_invocations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    server_name TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    arguments TEXT NOT NULL,
                    status TEXT NOT NULL,
                    execution_time_ms REAL,
                    raw_output_path TEXT,
                    truncated_output TEXT,
                    error_message TEXT,
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    target TEXT NOT NULL,
                    description TEXT,
                    evidence_ref TEXT,
                    remediation TEXT,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
                )
            """)
            conn.commit()

    def start_session(self, session_id: str, model_name: str, target_scope: Optional[List[str]] = None) -> Dict[str, Any]:
        """Registers a new assessment session."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        scope_str = json.dumps(target_scope or [])
        session_folder = os.path.join(self.runs_dir, session_id, "artifacts")
        os.makedirs(session_folder, exist_ok=True)

        with self._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO sessions (session_id, created_at, model_name, target_scope, status, summary)
                VALUES (?, ?, ?, ?, 'IN_PROGRESS', '')
            """, (session_id, now, model_name, scope_str))
            conn.commit()

        return {
            "session_id": session_id,
            "created_at": now,
            "model_name": model_name,
            "artifacts_dir": session_folder
        }

    def update_session(self, session_id: str, status: Optional[str] = None, summary: Optional[str] = None) -> None:
        """Updates session status or final summary."""
        with self._get_connection() as conn:
            if status and summary is not None:
                conn.execute("UPDATE sessions SET status = ?, summary = ? WHERE session_id = ?", (status, summary, session_id))
            elif status:
                conn.execute("UPDATE sessions SET status = ? WHERE session_id = ?", (status, session_id))
            elif summary is not None:
                conn.execute("UPDATE sessions SET summary = ? WHERE session_id = ?", (summary, session_id))
            conn.commit()

    def log_tool_invocation(
        self,
        session_id: str,
        server_name: str,
        tool_name: str,
        arguments: Dict[str, Any],
        raw_output: Any,
        status: str = "SUCCESS",
        execution_time_ms: float = 0.0,
        truncated_output: Optional[str] = None,
        error_message: Optional[str] = None
    ) -> Dict[str, Any]:
        """Logs a tool invocation and writes its full raw artifact to disk."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        time_slug = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        artifacts_dir = os.path.join(self.runs_dir, session_id, "artifacts")
        os.makedirs(artifacts_dir, exist_ok=True)

        artifact_filename = f"{time_slug}_{tool_name}.json"
        artifact_path = os.path.join(artifacts_dir, artifact_filename)

        artifact_data = {
            "session_id": session_id,
            "timestamp": now,
            "server_name": server_name,
            "tool_name": tool_name,
            "arguments": arguments,
            "status": status,
            "execution_time_ms": execution_time_ms,
            "raw_output": raw_output,
            "error_message": error_message
        }

        with open(artifact_path, "w", encoding="utf-8") as f:
            json.dump(artifact_data, f, indent=2, ensure_ascii=False)

        args_json = json.dumps(arguments, ensure_ascii=False)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO tool_invocations (
                    session_id, timestamp, server_name, tool_name, arguments,
                    status, execution_time_ms, raw_output_path, truncated_output, error_message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session_id, now, server_name, tool_name, args_json,
                status, execution_time_ms, artifact_path, truncated_output, error_message
            ))
            inv_id = cursor.lastrowid
            conn.commit()

        # Automatically extract findings from known structured tool responses
        self._auto_extract_findings(session_id, tool_name, arguments, raw_output, artifact_path)

        return {
            "invocation_id": inv_id,
            "session_id": session_id,
            "timestamp": now,
            "tool_name": tool_name,
            "status": status,
            "artifact_path": artifact_path
        }

    def _auto_extract_findings(
        self,
        session_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
        raw_output: Any,
        artifact_path: str
    ) -> None:
        """Inspects raw tool output and automatically extracts structured findings."""
        if not raw_output:
            return

        data = raw_output
        if isinstance(raw_output, str):
            try:
                data = json.loads(raw_output)
            except Exception:
                return

        if not isinstance(data, dict):
            return

        target = arguments.get("target_url") or arguments.get("hostname") or arguments.get("log_path") or arguments.get("target") or "Unknown Target"

        # Security Headers findings
        if tool_name == "check_security_headers" and "findings" in data:
            for idx, item in enumerate(data.get("findings", []), start=1):
                f_id = f"HDR-{idx:03d}"
                self.add_finding(
                    session_id=session_id,
                    finding_id=f_id,
                    severity=item.get("severity", "MEDIUM"),
                    title=item.get("issue", "Security Header Issue"),
                    target=str(target),
                    description=f"Missing or weak HTTP header: {item.get('header')}",
                    evidence_ref=os.path.basename(artifact_path),
                    remediation=item.get("recommendation", "Configure standard security headers.")
                )

        # Audit Log findings
        if tool_name == "analyze_audit_log" and "suspicious_patterns_detected" in data:
            for idx, item in enumerate(data.get("suspicious_patterns_detected", []), start=1):
                f_id = f"LOG-{idx:03d}"
                self.add_finding(
                    session_id=session_id,
                    finding_id=f_id,
                    severity=item.get("severity", "HIGH"),
                    title=item.get("pattern", "Suspicious Log Event"),
                    target=str(target),
                    description=item.get("details", "Suspicious pattern discovered in security audit log."),
                    evidence_ref=os.path.basename(artifact_path),
                    remediation="Investigate source IP and enforce lockout / rate limiting policies."
                )

        # TLS Cert findings
        if tool_name == "inspect_tls_cert" and "findings" in data:
            for idx, item in enumerate(data.get("findings", []), start=1):
                if item.get("severity") in ["CRITICAL", "HIGH", "MEDIUM"]:
                    f_id = f"TLS-{idx:03d}"
                    self.add_finding(
                        session_id=session_id,
                        finding_id=f_id,
                        severity=item.get("severity", "MEDIUM"),
                        title=item.get("issue", "TLS Certificate Warning"),
                        target=str(target),
                        description=item.get("details", ""),
                        evidence_ref=os.path.basename(artifact_path),
                        remediation="Renew TLS certificate or verify cipher suite configuration."
                    )

    def add_finding(
        self,
        session_id: str,
        finding_id: str,
        severity: str,
        title: str,
        target: str,
        description: str,
        evidence_ref: str,
        remediation: str
    ) -> None:
        """Adds a verified finding to the session's findings table."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO findings (
                    session_id, finding_id, severity, title, target,
                    description, evidence_ref, remediation, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (session_id, finding_id, severity.upper(), title, target, description, evidence_ref, remediation, now))
            conn.commit()

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves session metadata."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
            if not row:
                return None
            res = dict(row)
            try:
                res["target_scope"] = json.loads(res["target_scope"])
            except Exception:
                pass
            return res

    def get_session_invocations(self, session_id: str) -> List[Dict[str, Any]]:
        """Retrieves all tool invocations for a session."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM tool_invocations WHERE session_id = ? ORDER BY id ASC",
                (session_id,)
            ).fetchall()
            results = []
            for r in rows:
                item = dict(r)
                try:
                    item["arguments"] = json.loads(item["arguments"])
                except Exception:
                    pass
                results.append(item)
            return results

    def get_session_findings(self, session_id: str) -> List[Dict[str, Any]]:
        """Retrieves all findings recorded for a session."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM findings WHERE session_id = ? ORDER BY id ASC",
                (session_id,)
            ).fetchall()
            return [dict(r) for r in rows]
