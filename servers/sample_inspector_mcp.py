#!/usr/bin/env python3
"""
Sample Safe Reference MCP Server (Security Inspector)
-----------------------------------------------------
Demonstrates the Model Context Protocol (MCP) JSON-RPC 2.0 stdio contract.
All tools are purely read-only and defensive:
  - check_security_headers: Inspects HTTP headers for security best practices.
  - analyze_audit_log: Analyzes local audit/event logs for security anomalies.
  - inspect_tls_cert: Inspects SSL/TLS certificate details and validity.
  - check_host_reachability (recon mode): Verifies socket connectivity & latency.

Standard stdio transport:
  - Reads JSON-RPC requests from stdin.
  - Writes JSON-RPC responses to stdout (line-delimited).
  - Diagnostic logs are directed strictly to stderr.
"""

import sys
import os
import json
import socket
import ssl
import re
import datetime
import argparse
from typing import Any, Dict, List
import urllib.parse
import urllib.request
import urllib.error

# Server Metadata
SERVER_NAME = "security_inspector"
SERVER_VERSION = "1.0.0"
PROTOCOL_VERSION = "2024-11-05"


def log_debug(message: str) -> None:
    """Write debug output to stderr without polluting stdout."""
    sys.stderr.write(f"[{SERVER_NAME}] {message}\n")
    sys.stderr.flush()


# ============================================================================
# Tool Implementations (Defensive & Read-Only)
# ============================================================================

def check_security_headers(target_url: str, timeout: int = 10) -> Dict[str, Any]:
    """Inspects HTTP headers of target_url for security headers and potential disclosures."""
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    parsed = urllib.parse.urlparse(target_url)
    hostname = parsed.hostname or target_url

    results = {
        "target_url": target_url,
        "hostname": hostname,
        "scan_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status_code": None,
        "headers_found": {},
        "missing_security_headers": [],
        "misconfigured_headers": [],
        "information_disclosures": [],
        "overall_grade": "A",
        "score_percentage": 100,
        "findings": []
    }

    # Desired security headers and their evaluation criteria
    expected_headers = {
        "Content-Security-Policy": {
            "description": "Restricts sources of executable scripts, stylesheets, and assets",
            "weight": 25
        },
        "Strict-Transport-Security": {
            "description": "Enforces HTTPS connections (HSTS)",
            "weight": 25
        },
        "X-Content-Type-Options": {
            "description": "Prevents MIME-type sniffing (should be 'nosniff')",
            "weight": 15
        },
        "X-Frame-Options": {
            "description": "Protects against clickjacking attacks (DENY or SAMEORIGIN)",
            "weight": 15
        },
        "Referrer-Policy": {
            "description": "Controls referrer information passed in requests",
            "weight": 10
        },
        "Permissions-Policy": {
            "description": "Restricts browser feature usage (camera, microphone, geolocation)",
            "weight": 10
        }
    }

    req = urllib.request.Request(
        target_url,
        headers={"User-Agent": "MCP-Agent-Host-SecurityInspector/1.0 (Defensive Audit)"}
    )

    ctx = ssl.create_default_context()
    # For testing self-signed or internal endpoints gracefully
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    penalty = 0
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
            results["status_code"] = response.status
            raw_headers = dict(response.headers)
            results["headers_found"] = {k: v for k, v in raw_headers.items() if not k.lower().startswith("set-cookie")}

            # Evaluate Security Headers
            for header_name, meta in expected_headers.items():
                found_val = None
                for hk, hv in raw_headers.items():
                    if hk.lower() == header_name.lower():
                        found_val = hv
                        break

                if not found_val:
                    results["missing_security_headers"].append(header_name)
                    penalty += meta["weight"]
                    results["findings"].append({
                        "header": header_name,
                        "severity": "HIGH" if meta["weight"] >= 20 else "MEDIUM",
                        "issue": f"Missing critical security header '{header_name}'",
                        "recommendation": f"Configure '{header_name}' to enforce defensive browser policies."
                    })
                else:
                    # Check for weak configuration
                    val_lower = found_val.lower()
                    if header_name == "X-Content-Type-Options" and "nosniff" not in val_lower:
                        results["misconfigured_headers"].append(header_name)
                        penalty += 10
                        results["findings"].append({
                            "header": header_name,
                            "severity": "MEDIUM",
                            "issue": "X-Content-Type-Options should be strictly set to 'nosniff'",
                            "recommendation": "Set header: X-Content-Type-Options: nosniff"
                        })
                    elif header_name == "Strict-Transport-Security" and "max-age" not in val_lower:
                        results["misconfigured_headers"].append(header_name)
                        penalty += 15
                        results["findings"].append({
                            "header": header_name,
                            "severity": "HIGH",
                            "issue": "HSTS header missing valid max-age directive",
                            "recommendation": "Configure HSTS with: max-age=31536000; includeSubDomains"
                        })
                    elif header_name == "Content-Security-Policy" and "unsafe-inline" in val_lower:
                        results["misconfigured_headers"].append(header_name)
                        penalty += 10
                        results["findings"].append({
                            "header": header_name,
                            "severity": "MEDIUM",
                            "issue": "CSP contains 'unsafe-inline' which weakens XSS defenses",
                            "recommendation": "Use nonce-based or hash-based CSP instead of 'unsafe-inline'."
                        })

            # Check for Information Disclosures
            for disc_header in ["Server", "X-Powered-By", "X-AspNet-Version", "X-Runtime"]:
                for hk, hv in raw_headers.items():
                    if hk.lower() == disc_header.lower():
                        results["information_disclosures"].append({hk: hv})
                        penalty += 5
                        results["findings"].append({
                            "header": hk,
                            "severity": "LOW",
                            "issue": f"Information disclosure detected in '{hk}': '{hv}'",
                            "recommendation": f"Suppress or obfuscate the '{hk}' banner in web server configuration."
                        })

    except urllib.error.HTTPError as e:
        results["status_code"] = e.code
        results["error"] = f"HTTP Error {e.code}: {e.reason}"
    except Exception as e:
        results["error"] = f"Connection failed: {str(e)}"
        # Return structured fallback for mock/offline testing
        results["overall_grade"] = "F"
        results["score_percentage"] = 0
        results["findings"].append({
            "header": "Connection",
            "severity": "HIGH",
            "issue": f"Target unreachable: {str(e)}",
            "recommendation": "Verify target URL is active and accessible."
        })
        return results

    # Calculate overall grade
    final_score = max(0, 100 - penalty)
    results["score_percentage"] = final_score
    if final_score >= 90:
        results["overall_grade"] = "A"
    elif final_score >= 75:
        results["overall_grade"] = "B"
    elif final_score >= 60:
        results["overall_grade"] = "C"
    elif final_score >= 40:
        results["overall_grade"] = "D"
    else:
        results["overall_grade"] = "F"

    return results


def analyze_audit_log(log_path: str, keywords: List[str] = None) -> Dict[str, Any]:
    """Analyzes a local log or JSON audit event file for security warnings, error spikes, and anomalies."""
    if not os.path.exists(log_path):
        return {
            "error": f"Log file not found at path: {log_path}",
            "log_path": log_path,
            "total_lines": 0
        }

    default_keywords = ["ALERT", "ERROR", "WARNING", "Failed", "Access Denied", "lockout", "invalid", "403", "401"]
    search_keywords = keywords if keywords else default_keywords

    metrics = {
        "log_path": os.path.abspath(log_path),
        "file_size_bytes": os.path.getsize(log_path),
        "total_lines_inspected": 0,
        "matched_events_count": 0,
        "severity_breakdown": {"ALERT": 0, "ERROR": 0, "WARNING": 0, "NOTICE": 0},
        "flagged_events": [],
        "suspicious_patterns_detected": []
    }

    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            for line_no, raw_line in enumerate(f, start=1):
                metrics["total_lines_inspected"] += 1
                line = raw_line.strip()
                if not line:
                    continue

                matched = [kw for kw in search_keywords if re.search(re.escape(kw), line, re.IGNORECASE)]
                if matched:
                    metrics["matched_events_count"] += 1
                    sev = "NOTICE"
                    if "ALERT" in line.upper():
                        sev = "ALERT"
                    elif "ERROR" in line.upper():
                        sev = "ERROR"
                    elif "WARNING" in line.upper():
                        sev = "WARNING"
                    metrics["severity_breakdown"][sev] = metrics["severity_breakdown"].get(sev, 0) + 1

                    if len(metrics["flagged_events"]) < 50:  # Bound memory / output
                        metrics["flagged_events"].append({
                            "line_number": line_no,
                            "severity": sev,
                            "matched_keywords": matched,
                            "log_content": line
                        })

        # Pattern heuristics
        if metrics["severity_breakdown"].get("ALERT", 0) > 0:
            metrics["suspicious_patterns_detected"].append({
                "pattern": "High Severity Security Alerts Triggered",
                "severity": "HIGH",
                "details": f"{metrics['severity_breakdown']['ALERT']} ALERT level events were discovered in log stream."
            })
        if any("lockout" in e["log_content"].lower() for e in metrics["flagged_events"]):
            metrics["suspicious_patterns_detected"].append({
                "pattern": "Account Lockout Event",
                "severity": "MEDIUM",
                "details": "Account lockout triggered, likely due to repeated failed authentication attempts."
            })
        if any("403" in e["log_content"] for e in metrics["flagged_events"]):
            metrics["suspicious_patterns_detected"].append({
                "pattern": "Unauthorized Resource Access Probes",
                "severity": "MEDIUM",
                "details": "Multiple HTTP 403 Forbidden responses detected indicating unauthorized path enumeration."
            })

    except Exception as e:
        metrics["error"] = f"Failed to parse log file: {str(e)}"

    return metrics


def inspect_tls_cert(hostname: str, port: int = 443) -> Dict[str, Any]:
    """Inspects the SSL/TLS certificate for an authorized target hostname."""
    # Strip any protocol if mistakenly supplied
    if hostname.startswith("http://") or hostname.startswith("https://"):
        parsed = urllib.parse.urlparse(hostname)
        hostname = parsed.hostname or hostname

    res = {
        "hostname": hostname,
        "port": port,
        "inspection_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "is_valid": False,
        "subject": {},
        "issuer": {},
        "valid_from": None,
        "valid_until": None,
        "days_remaining": None,
        "san_domains": [],
        "tls_version": None,
        "cipher": None,
        "findings": []
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                res["tls_version"] = ssock.version()
                res["cipher"] = ssock.cipher()

                # Parse subject & issuer
                if cert:
                    for item in cert.get("subject", ()):
                        for k, v in item:
                            res["subject"][k] = v
                    for item in cert.get("issuer", ()):
                        for k, v in item:
                            res["issuer"][k] = v

                    res["valid_from"] = cert.get("notBefore")
                    res["valid_until"] = cert.get("notAfter")

                    # Parse SANs
                    sans = []
                    for k, v in cert.get("subjectAltName", ()):
                        if k.lower() == "dns":
                            sans.append(v)
                    res["san_domains"] = sans

                    # Calculate expiration
                    if res["valid_until"]:
                        expire_dt = datetime.datetime.strptime(res["valid_until"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
                        now_dt = datetime.datetime.now(datetime.timezone.utc)
                        days = (expire_dt - now_dt).days
                        res["days_remaining"] = days
                        res["is_valid"] = days > 0

                        if days < 0:
                            res["findings"].append({
                                "severity": "CRITICAL",
                                "issue": "TLS Certificate is EXPIRED",
                                "details": f"Certificate expired {abs(days)} days ago on {res['valid_until']}"
                            })
                        elif days < 30:
                            res["findings"].append({
                                "severity": "MEDIUM",
                                "issue": "TLS Certificate expiring soon",
                                "details": f"Certificate expires in {days} days on {res['valid_until']}"
                            })
                        else:
                            res["findings"].append({
                                "severity": "INFORMATIONAL",
                                "issue": "TLS Certificate is active and valid",
                                "details": f"Certificate valid for {days} more days"
                            })

    except Exception as e:
        res["error"] = str(e)
        res["findings"].append({
            "severity": "HIGH",
            "issue": f"TLS Handshake failed: {str(e)}",
            "details": "Could not establish secure TLS connection to target."
        })

    return res


def check_host_reachability(target: str, port: int = 80) -> Dict[str, Any]:
    """Defensive socket ping & reachability check (recon mode tool)."""
    start_time = datetime.datetime.now()
    res = {
        "target": target,
        "port": port,
        "reachable": False,
        "latency_ms": None,
        "resolved_ip": None,
        "timestamp": start_time.isoformat()
    }

    try:
        ip = socket.gethostbyname(target)
        res["resolved_ip"] = ip
        with socket.create_connection((ip, port), timeout=5) as sock:
            end_time = datetime.datetime.now()
            res["reachable"] = True
            res["latency_ms"] = round((end_time - start_time).total_seconds() * 1000, 2)
    except Exception as e:
        res["error"] = str(e)

    return res


# ============================================================================
# MCP Tool Registry Definitions
# ============================================================================

def get_tools_definition(mode: str = "standard") -> List[Dict[str, Any]]:
    """Returns the MCP tool definitions for tools/list."""
    tools = [
        {
            "name": "check_security_headers",
            "description": "Inspects HTTP response headers of an authorized web endpoint for defensive security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) and information disclosures.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target_url": {
                        "type": "string",
                        "description": "The target HTTP/HTTPS URL to inspect (e.g. 'https://example.com')"
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Connection timeout in seconds (default: 10)",
                        "default": 10
                    }
                },
                "required": ["target_url"]
            }
        },
        {
            "name": "analyze_audit_log",
            "description": "Safely reads and parses a local security log or audit event file to detect unauthorized access attempts, 403 spikes, failed authentications, and critical alerts.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "log_path": {
                        "type": "string",
                        "description": "Path to the log file to inspect (e.g. './sample_data/audit_sample.log')"
                    },
                    "keywords": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional custom keywords to search for"
                    }
                },
                "required": ["log_path"]
            }
        },
        {
            "name": "inspect_tls_cert",
            "description": "Inspects the SSL/TLS certificate for an authorized target hostname, checking validity period, issuer, expiration, and Subject Alternative Names (SANs).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "hostname": {
                        "type": "string",
                        "description": "Target hostname (e.g. 'example.com')"
                    },
                    "port": {
                        "type": "integer",
                        "description": "Target TLS port (default: 443)",
                        "default": 443
                    }
                },
                "required": ["hostname"]
            }
        }
    ]

    if mode == "recon":
        tools.append({
            "name": "check_host_reachability",
            "description": "Verifies network reachability and latency to an authorized host on a specific port.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Hostname or IP address to check"
                    },
                    "port": {
                        "type": "integer",
                        "description": "Port number to test (default: 80)",
                        "default": 80
                    }
                },
                "required": ["target"]
            }
        })

    return tools


# ============================================================================
# MCP JSON-RPC 2.0 Dispatcher & Stdio Loop
# ============================================================================

def handle_json_rpc(request: Dict[str, Any], mode: str) -> Dict[str, Any]:
    """Handles an incoming JSON-RPC 2.0 MCP request."""
    msg_id = request.get("id")
    method = request.get("method")
    params = request.get("params", {})

    log_debug(f"Handling method: {method} (id: {msg_id})")

    # 1. MCP Handshake: initialize
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {
                        "listChanged": False
                    }
                },
                "serverInfo": {
                    "name": SERVER_NAME,
                    "version": SERVER_VERSION
                }
            }
        }

    # 2. MCP Notification: notifications/initialized
    if method == "notifications/initialized":
        log_debug("MCP initialized notification acknowledged.")
        return None  # Notifications do not receive a response

    # 3. Ping
    if method == "ping":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {}
        }

    # 4. MCP Tools: tools/list
    if method == "tools/list":
        tools = get_tools_definition(mode)
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "tools": tools
            }
        }

    # 5. MCP Tools: tools/call
    if method == "tools/call":
        tool_name = params.get("name")
        args = params.get("arguments", {})
        log_debug(f"Executing tool '{tool_name}' with args {args}")

        try:
            if tool_name == "check_security_headers":
                res_data = check_security_headers(
                    target_url=args.get("target_url"),
                    timeout=args.get("timeout", 10)
                )
            elif tool_name == "analyze_audit_log":
                res_data = analyze_audit_log(
                    log_path=args.get("log_path"),
                    keywords=args.get("keywords")
                )
            elif tool_name == "inspect_tls_cert":
                res_data = inspect_tls_cert(
                    hostname=args.get("hostname"),
                    port=args.get("port", 443)
                )
            elif tool_name == "check_host_reachability" and mode == "recon":
                res_data = check_host_reachability(
                    target=args.get("target"),
                    port=args.get("port", 80)
                )
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32601,
                        "message": f"Tool '{tool_name}' not found on server '{SERVER_NAME}'"
                    }
                }

            formatted_text = json.dumps(res_data, indent=2)
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": formatted_text
                        }
                    ],
                    "isError": "error" in res_data
                }
            }
        except Exception as e:
            log_debug(f"Tool execution error: {str(e)}")
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps({"error": str(e)}, indent=2)
                        }
                    ],
                    "isError": True
                }
            }

    # Unknown method
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {
            "code": -32601,
            "message": f"Method '{method}' not implemented."
        }
    }


def run_stdio_server(mode: str = "standard") -> None:
    """Runs the MCP server over standard I/O."""
    log_debug(f"Starting MCP stdio server in '{mode}' mode. Awaiting JSON-RPC requests...")

    # Force stdin and stdout to utf-8 text streams
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break  # EOF reached (host closed connection)

            line = line.strip()
            if not line:
                continue

            # Check if input has Content-Length header prefix
            if line.startswith("Content-Length:"):
                # Read until empty line
                content_len = int(line.split(":")[1].strip())
                while True:
                    hdr = sys.stdin.readline().strip()
                    if not hdr:
                        break
                body = sys.stdin.read(content_len)
                request = json.loads(body)
            else:
                request = json.loads(line)

            response = handle_json_rpc(request, mode)
            if response is not None:
                output = json.dumps(response) + "\n"
                sys.stdout.write(output)
                sys.stdout.flush()

        except json.JSONDecodeError as e:
            log_debug(f"JSON decode error: {e}")
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "Parse error: invalid JSON"}
            }
            sys.stdout.write(json.dumps(err_resp) + "\n")
            sys.stdout.flush()
        except KeyboardInterrupt:
            log_debug("Server interrupted by operator.")
            break
        except Exception as e:
            log_debug(f"Unexpected server loop exception: {e}")
            break

    log_debug("MCP stdio server terminated.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sample Safe Reference MCP Server (Security Inspector)")
    parser.add_argument("--mode", choices=["standard", "recon"], default="standard",
                        help="Server mode: 'standard' (headers, logs, tls) or 'recon' (connectivity)")
    args = parser.parse_args()
    run_stdio_server(mode=args.mode)
