#!/usr/bin/env python3
"""
DNS & Email Posture Auditor MCP Server
--------------------------------------
Safe, passive, read-only MCP server for auditing DNS records, email authentication
posture (SPF, DMARC, DKIM), and RFC 9116 security.txt disclosures.

Tools:
  - check_dns_records: Queries A, AAAA, MX, NS, and CAA records with posture notes.
  - check_email_auth: Audits SPF, DMARC, and DKIM TXT records.
  - check_security_txt: Safely fetches https://<domain>/.well-known/security.txt.

Standard stdio transport:
  - Reads JSON-RPC 2.0 requests from stdin.
  - Writes newline-delimited JSON-RPC 2.0 responses to stdout.
  - Diagnostic logs are directed strictly to stderr.
"""

import argparse
import datetime
import json
import re
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

try:
    import dns.exception
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    dns = None  # type: ignore[assignment]
    HAS_DNSPYTHON = False

# Server Metadata
SERVER_NAME = "dns_email_auditor"
SERVER_VERSION = "1.0.0"
PROTOCOL_VERSION = "2024-11-05"

DEFAULT_DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1"]
MAX_DKIM_SELECTORS = 20
MAX_RECORD_ITEMS = 20
DEFAULT_DNS_TIMEOUT = 5.0
DEFAULT_HTTP_TIMEOUT = 5
MAX_SECURITY_TXT_BYTES = 16384
MAX_SECURITY_TXT_PREVIEW_CHARS = 1500
USER_AGENT = "MCP-Agent-Host-DnsEmailAuditor/1.0 (Passive Defensive Audit)"

_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def log_debug(message: str) -> None:
    """Write debug output to stderr without polluting stdout."""
    sys.stderr.write(f"[{SERVER_NAME}] {message}\n")
    sys.stderr.flush()


def normalize_domain(raw_domain: str) -> str:
    """
    Normalize a domain or URL input into a lowercase bare hostname.
    Strips schemes (http://, https://), userinfo, ports, paths, queries,
    fragments, and trailing slashes/dots.
    """
    if not isinstance(raw_domain, str):
        raise ValueError("Domain must be a non-empty string.")

    cleaned = raw_domain.strip()
    if not cleaned:
        raise ValueError("Domain must not be empty.")

    # Reject obvious whitespace inside input before parsing
    if any(ch.isspace() for ch in cleaned):
        raise ValueError(f"Invalid domain '{raw_domain}': contains whitespace.")

    candidate = cleaned if "://" in cleaned else f"http://{cleaned}"
    parsed = urllib.parse.urlparse(candidate)
    hostname = (parsed.hostname or "").strip().lower().rstrip(".")

    if not hostname:
        raise ValueError(f"Could not extract a valid hostname from '{raw_domain}'.")

    if len(hostname) > 253:
        raise ValueError(f"Domain '{hostname}' exceeds maximum DNS length of 253 characters.")

    # Allow valid IPv4/IPv6 only as invalid domain? Wait: check standard DNS labels or localhost
    labels = hostname.split(".")
    for label in labels:
        # Allow underscore-prefixed labels only if someone passed a subdomain, though normal domains use LDH
        if not _DOMAIN_LABEL_RE.match(label):
            raise ValueError(f"Invalid DNS label '{label}' in domain '{raw_domain}'.")

    return hostname


def _query_socket_ip_records(qname: str, rdtype: str) -> Dict[str, Any]:
    """Fallback A/AAAA lookup using stdlib socket.getaddrinfo."""
    family = socket.AF_INET if rdtype == "A" else socket.AF_INET6
    try:
        infos = socket.getaddrinfo(qname, None, family=family, type=socket.SOCK_STREAM)
        seen: List[str] = []
        for info in infos:
            addr = info[4][0]
            if addr not in seen:
                seen.append(addr)
                if len(seen) >= MAX_RECORD_ITEMS:
                    break
        if seen:
            return {"status": "ok", "values": seen, "backend": "socket"}
        return {"status": "not_found", "values": [], "backend": "socket"}
    except socket.gaierror as e:
        err_no = getattr(e, "errno", None)
        # EAI_NONAME / EAI_NODATA / Windows WSAHOST_NOT_FOUND(11001) / WSANO_DATA(11004)
        not_found_errnos = {
            getattr(socket, "EAI_NONAME", -2),
            getattr(socket, "EAI_NODATA", -5),
            11001,
            11004,
        }
        if err_no in not_found_errnos:
            return {"status": "not_found", "values": [], "backend": "socket", "detail": str(e)}
        return {"status": "error", "values": [], "backend": "socket", "error": str(e)}
    except Exception as e:
        return {"status": "error", "values": [], "backend": "socket", "error": str(e)}


def _format_dnspython_rdata(rdtype: str, rdata: Any) -> Any:
    """Formats a dnspython rdata object into a compact JSON-serializable value."""
    if rdtype in ("A", "AAAA"):
        return str(rdata.address)
    if rdtype == "MX":
        return {
            "preference": int(rdata.preference),
            "exchange": str(rdata.exchange).rstrip("."),
        }
    if rdtype == "NS":
        return str(rdata.target).rstrip(".")
    if rdtype == "CAA":
        tag = rdata.tag.decode("utf-8", errors="replace") if isinstance(rdata.tag, bytes) else str(rdata.tag)
        val = rdata.value.decode("utf-8", errors="replace") if isinstance(rdata.value, bytes) else str(rdata.value)
        return {"flags": int(rdata.flags), "tag": tag, "value": val}
    if rdtype == "TXT":
        if hasattr(rdata, "strings"):
            return b"".join(
                s if isinstance(s, bytes) else str(s).encode("utf-8", errors="replace")
                for s in rdata.strings
            ).decode("utf-8", errors="replace")
        return str(rdata).strip('"')
    return str(rdata)


def _query_dns_record(qname: str, rdtype: str, timeout: float = DEFAULT_DNS_TIMEOUT) -> Dict[str, Any]:
    """
    Queries a single DNS record type using dnspython if installed,
    falling back to socket.getaddrinfo for A/AAAA records.
    """
    if HAS_DNSPYTHON and dns is not None:
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = timeout
            resolver.timeout = min(timeout, 3.0)
            answers = resolver.resolve(qname, rdtype)
            values = [_format_dnspython_rdata(rdtype, r) for r in answers]
            if rdtype == "MX":
                values.sort(key=lambda item: item["preference"])
            return {
                "status": "ok" if values else "not_found",
                "values": values[:MAX_RECORD_ITEMS],
                "backend": "dnspython",
            }
        except dns.resolver.NXDOMAIN:
            return {"status": "nxdomain", "values": [], "backend": "dnspython"}
        except dns.resolver.NoAnswer:
            return {"status": "not_found", "values": [], "backend": "dnspython"}
        except dns.exception.Timeout:
            return {
                "status": "error",
                "values": [],
                "backend": "dnspython",
                "error": f"DNS {rdtype} query for '{qname}' timed out after {timeout}s.",
            }
        except Exception as e:
            return {
                "status": "error",
                "values": [],
                "backend": "dnspython",
                "error": str(e),
            }

    if rdtype in ("A", "AAAA"):
        return _query_socket_ip_records(qname, rdtype)

    return {
        "status": "unavailable",
        "values": [],
        "backend": "none",
        "error": (
            f"Optional package 'dnspython' is not installed; "
            f"cannot query {rdtype} records without dnspython."
        ),
    }


# ============================================================================
# Tool Implementations (Passive & Read-Only)
# ============================================================================

def check_dns_records(domain: str) -> Dict[str, Any]:
    """Queries A, AAAA, MX, NS, and CAA records and reports DNS posture observations."""
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    try:
        normalized = normalize_domain(domain)
    except ValueError as e:
        return {
            "input_domain": domain,
            "scan_timestamp": timestamp,
            "error": str(e),
        }

    record_types = ["A", "AAAA", "MX", "NS", "CAA"]
    records: Dict[str, Dict[str, Any]] = {}
    for rdtype in record_types:
        records[rdtype] = _query_dns_record(normalized, rdtype)

    observations: List[Dict[str, str]] = []

    # NS redundancy observation
    ns_rec = records["NS"]
    if ns_rec["status"] == "ok":
        ns_count = len(ns_rec["values"])
        if ns_count < 2:
            observations.append({
                "category": "NS Redundancy",
                "severity": "MEDIUM",
                "observation": f"Only {ns_count} NS record found; lacking authoritative DNS redundancy.",
            })
        else:
            observations.append({
                "category": "NS Redundancy",
                "severity": "INFO",
                "observation": f"NS redundancy present ({ns_count} authoritative nameservers).",
            })
    elif ns_rec["status"] == "unavailable":
        observations.append({
            "category": "NS Redundancy",
            "severity": "INFO",
            "observation": "NS records not checked (dnspython unavailable).",
        })
    else:
        observations.append({
            "category": "NS Redundancy",
            "severity": "LOW",
            "observation": f"NS records returned status '{ns_rec['status']}'.",
        })

    # CAA observation
    caa_rec = records["CAA"]
    if caa_rec["status"] == "ok" and caa_rec["values"]:
        observations.append({
            "category": "CAA Policy",
            "severity": "INFO",
            "observation": f"CAA record(s) configured ({len(caa_rec['values'])} rule(s)) restricting certificate issuance.",
        })
    elif caa_rec["status"] in ("not_found", "nxdomain"):
        observations.append({
            "category": "CAA Policy",
            "severity": "LOW",
            "observation": "No CAA record found; any publicly trusted CA may issue certificates for this domain.",
        })
    elif caa_rec["status"] == "unavailable":
        observations.append({
            "category": "CAA Policy",
            "severity": "INFO",
            "observation": "CAA records not checked (dnspython unavailable).",
        })

    # MX presence observation
    mx_rec = records["MX"]
    if mx_rec["status"] == "ok" and mx_rec["values"]:
        observations.append({
            "category": "MX Presence",
            "severity": "INFO",
            "observation": f"MX records present ({len(mx_rec['values'])}); domain is configured to receive email.",
        })
    elif mx_rec["status"] in ("not_found", "nxdomain"):
        observations.append({
            "category": "MX Presence",
            "severity": "INFO",
            "observation": "No MX records found; domain does not advertise inbound mail exchangers.",
        })
    elif mx_rec["status"] == "unavailable":
        observations.append({
            "category": "MX Presence",
            "severity": "INFO",
            "observation": "MX records not checked (dnspython unavailable).",
        })

    # IPv4 / IPv6 observation
    a_vals = records["A"]["values"]
    aaaa_vals = records["AAAA"]["values"]
    if not a_vals and not aaaa_vals:
        observations.append({
            "category": "Host Addressing",
            "severity": "INFO",
            "observation": "Neither A nor AAAA records resolved for apex domain.",
        })
    elif a_vals and not aaaa_vals:
        observations.append({
            "category": "Host Addressing",
            "severity": "INFO",
            "observation": "IPv4 (A) present; no IPv6 (AAAA) record configured.",
        })

    return {
        "domain": normalized,
        "input_domain": domain,
        "scan_timestamp": timestamp,
        "dnspython_available": HAS_DNSPYTHON,
        "records": records,
        "posture_observations": observations,
    }


def _extract_dmarc_tag(record: str, tag: str) -> Optional[str]:
    match = re.search(rf"(?:^|;)\s*{re.escape(tag)}=([^;\s]+)", record, re.IGNORECASE)
    return match.group(1).strip().lower() if match else None


def check_email_auth(domain: str, dkim_selectors: Optional[List[str]] = None) -> Dict[str, Any]:
    """Audits SPF, DMARC, and DKIM TXT records for a domain."""
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    try:
        normalized = normalize_domain(domain)
    except ValueError as e:
        return {
            "input_domain": domain,
            "scan_timestamp": timestamp,
            "error": str(e),
        }

    # Prepare bounded, sanitized DKIM selector list
    raw_selectors = dkim_selectors if dkim_selectors else DEFAULT_DKIM_SELECTORS
    selectors: List[str] = []
    for sel in raw_selectors:
        if not isinstance(sel, str):
            continue
        cleaned_sel = sel.strip().lower().rstrip(".")
        if cleaned_sel and cleaned_sel not in selectors:
            selectors.append(cleaned_sel)
            if len(selectors) >= MAX_DKIM_SELECTORS:
                break
    if not selectors:
        selectors = list(DEFAULT_DKIM_SELECTORS)

    findings: List[Dict[str, str]] = []

    # 1. SPF on apex domain
    txt_apex = _query_dns_record(normalized, "TXT")
    spf_info: Dict[str, Any] = {
        "qname": normalized,
        "status": txt_apex["status"],
        "present": False,
        "records": [],
        "multiple_spf_records": False,
        "all_mechanism": None,
        "has_risky_plus_all": False,
    }
    if txt_apex["status"] == "ok":
        spf_records = [
            rec[:500] for rec in txt_apex["values"]
            if isinstance(rec, str) and rec.lower().lstrip().startswith("v=spf1")
        ]
        spf_info["records"] = spf_records[:5]
        spf_info["present"] = len(spf_records) > 0
        spf_info["multiple_spf_records"] = len(spf_records) > 1

        if not spf_records:
            spf_info["status"] = "missing"
            findings.append({
                "control": "SPF",
                "severity": "MEDIUM",
                "issue": "No SPF (v=spf1) TXT record found.",
                "recommendation": "Publish a restrictive SPF TXT record ending with '-all' or '~all'.",
            })
        else:
            if len(spf_records) > 1:
                findings.append({
                    "control": "SPF",
                    "severity": "HIGH",
                    "issue": f"Multiple SPF records detected ({len(spf_records)}); RFC 7208 treats this as PermError.",
                    "recommendation": "Consolidate all authorized senders into a single v=spf1 TXT record.",
                })
            tokens = spf_records[0].lower().split()
            all_mechs = [t for t in tokens if t in ("+all", "-all", "~all", "?all", "all")]
            if all_mechs:
                mech = "+all" if all_mechs[-1] == "all" else all_mechs[-1]
                spf_info["all_mechanism"] = mech
                if mech == "+all":
                    spf_info["has_risky_plus_all"] = True
                    spf_info["status"] = "risky"
                    findings.append({
                        "control": "SPF",
                        "severity": "HIGH",
                        "issue": "SPF record uses '+all', permitting any host on the internet to spoof this domain.",
                        "recommendation": "Replace '+all' with '-all' (hard fail) or '~all' (soft fail).",
                    })
                elif mech == "?all":
                    spf_info["status"] = "weak"
                    findings.append({
                        "control": "SPF",
                        "severity": "MEDIUM",
                        "issue": "SPF record uses neutral '?all' mechanism, offering weak spoofing protection.",
                        "recommendation": "Tighten SPF policy to '-all' or '~all'.",
                    })
                else:
                    spf_info["status"] = "pass"
            else:
                spf_info["status"] = "weak"
                findings.append({
                    "control": "SPF",
                    "severity": "LOW",
                    "issue": "SPF record does not specify an explicit terminal 'all' mechanism.",
                    "recommendation": "End the SPF record with '-all' or '~all'.",
                })
    elif txt_apex["status"] in ("not_found", "nxdomain"):
        spf_info["status"] = "missing"
        findings.append({
            "control": "SPF",
            "severity": "MEDIUM",
            "issue": "No TXT/SPF record found on domain.",
            "recommendation": "Publish a v=spf1 TXT record to authorize legitimate mail servers.",
        })
    elif "error" in txt_apex:
        spf_info["error"] = txt_apex["error"]

    # 2. DMARC on _dmarc.<domain>
    dmarc_qname = f"_dmarc.{normalized}"
    txt_dmarc = _query_dns_record(dmarc_qname, "TXT")
    dmarc_info: Dict[str, Any] = {
        "qname": dmarc_qname,
        "status": txt_dmarc["status"],
        "present": False,
        "policy": "missing",
        "subdomain_policy": None,
        "rua_configured": False,
        "record": None,
    }
    if txt_dmarc["status"] == "ok":
        dmarc_records = [
            rec[:500] for rec in txt_dmarc["values"]
            if isinstance(rec, str) and rec.lower().lstrip().startswith("v=dmarc1")
        ]
        if dmarc_records:
            dmarc_rec = dmarc_records[0]
            policy = _extract_dmarc_tag(dmarc_rec, "p") or "unknown"
            sp_policy = _extract_dmarc_tag(dmarc_rec, "sp")
            rua = _extract_dmarc_tag(dmarc_rec, "rua")
            dmarc_info["present"] = True
            dmarc_info["record"] = dmarc_rec
            dmarc_info["policy"] = policy
            dmarc_info["subdomain_policy"] = sp_policy
            dmarc_info["rua_configured"] = bool(rua)

            if policy == "none":
                dmarc_info["status"] = "weak"
                findings.append({
                    "control": "DMARC",
                    "severity": "MEDIUM",
                    "issue": "DMARC policy is 'p=none' (monitoring only); unauthenticated mail is not quarantined or rejected.",
                    "recommendation": "Transition DMARC policy to 'p=quarantine' and ultimately 'p=reject'.",
                })
            elif policy in ("quarantine", "reject"):
                dmarc_info["status"] = "pass"
                findings.append({
                    "control": "DMARC",
                    "severity": "INFO",
                    "issue": f"Enforcing DMARC policy 'p={policy}' is configured.",
                    "recommendation": "Monitor DMARC aggregate reports (rua) periodically.",
                })
            else:
                dmarc_info["status"] = "weak"
                findings.append({
                    "control": "DMARC",
                    "severity": "MEDIUM",
                    "issue": f"DMARC record present but policy tag 'p=' is '{policy}'.",
                    "recommendation": "Ensure valid DMARC policy (p=quarantine or p=reject).",
                })
        else:
            dmarc_info["status"] = "missing"
            findings.append({
                "control": "DMARC",
                "severity": "MEDIUM",
                "issue": "No valid v=DMARC1 record found at _dmarc subdomain.",
                "recommendation": "Publish a DMARC TXT record at _dmarc.<domain>.",
            })
    elif txt_dmarc["status"] in ("not_found", "nxdomain"):
        dmarc_info["status"] = "missing"
        dmarc_info["policy"] = "missing"
        findings.append({
            "control": "DMARC",
            "severity": "MEDIUM",
            "issue": "DMARC record is missing (_dmarc subdomain returned no record).",
            "recommendation": "Publish a DMARC TXT record starting with 'v=DMARC1; p=quarantine;'.",
        })
    else:
        dmarc_info["policy"] = "unknown"
        if "error" in txt_dmarc:
            dmarc_info["error"] = txt_dmarc["error"]

    # 3. DKIM selectors on <selector>._domainkey.<domain>
    found_selectors: List[Dict[str, Any]] = []
    not_found_selectors: List[str] = []
    unavailable_selectors: List[str] = []
    error_selectors: List[Dict[str, str]] = []

    for sel in selectors:
        dkim_qname = f"{sel}._domainkey.{normalized}"
        dkim_res = _query_dns_record(dkim_qname, "TXT")
        if dkim_res["status"] == "ok":
            dkim_records = [
                r for r in dkim_res["values"]
                if isinstance(r, str) and ("v=dkim1" in r.lower() or "p=" in r.lower())
            ]
            if dkim_records:
                rec_text = dkim_records[0]
                key_match = re.search(r"(?:^|;)\s*p=([^;\s]*)", rec_text, re.IGNORECASE)
                key_present = bool(key_match and key_match.group(1))
                found_selectors.append({
                    "selector": sel,
                    "qname": dkim_qname,
                    "key_present": key_present,
                    "record_preview": rec_text[:200],
                })
            else:
                not_found_selectors.append(sel)
        elif dkim_res["status"] in ("not_found", "nxdomain"):
            not_found_selectors.append(sel)
        elif dkim_res["status"] == "unavailable":
            unavailable_selectors.append(sel)
        else:
            error_selectors.append({"selector": sel, "error": dkim_res.get("error", "Unknown error")})

    if found_selectors:
        findings.append({
            "control": "DKIM",
            "severity": "INFO",
            "issue": f"Found {len(found_selectors)} DKIM selector(s): {', '.join(s['selector'] for s in found_selectors)}.",
            "recommendation": "Verify active mail senders sign outbound mail with valid DKIM keys.",
        })
    elif not unavailable_selectors:
        findings.append({
            "control": "DKIM",
            "severity": "INFO",
            "issue": f"No DKIM records found for tested default/provided selectors ({', '.join(selectors)}).",
            "recommendation": "Domain may use a custom DKIM selector; supply known selectors to verify.",
        })

    result: Dict[str, Any] = {
        "domain": normalized,
        "input_domain": domain,
        "scan_timestamp": timestamp,
        "spf": spf_info,
        "dmarc": dmarc_info,
        "dkim": {
            "checked_selectors": selectors,
            "found_selectors": found_selectors,
            "not_found_count": len(not_found_selectors),
            "unavailable_count": len(unavailable_selectors),
            "errors": error_selectors,
        },
        "findings": findings,
    }

    if txt_apex["status"] == "unavailable" or txt_dmarc["status"] == "unavailable":
        result["error"] = (
            "Optional package 'dnspython' is not installed; TXT record queries "
            "(SPF, DMARC, DKIM) require dnspython."
        )

    return result


def _parse_security_txt_fields(content: str) -> Dict[str, List[str]]:
    """Extracts standard RFC 9116 directive fields from security.txt content."""
    fields: Dict[str, List[str]] = {}
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-----BEGIN PGP") or line.startswith("-----END PGP"):
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key_clean = key.strip()
        val_clean = value.strip()
        if not key_clean or " " in key_clean:
            continue
        bucket = fields.setdefault(key_clean, [])
        if len(bucket) < 10:
            bucket.append(val_clean[:300])
        if len(fields) >= 25:
            break
    return fields


def check_security_txt(domain: str) -> Dict[str, Any]:
    """Safely fetches and parses https://<domain>/.well-known/security.txt."""
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    try:
        normalized = normalize_domain(domain)
    except ValueError as e:
        return {
            "input_domain": domain,
            "scan_timestamp": timestamp,
            "present": False,
            "error": str(e),
        }

    target_url = f"https://{normalized}/.well-known/security.txt"
    req = urllib.request.Request(
        target_url,
        headers={"User-Agent": USER_AGENT},
        method="GET",
    )
    ctx = ssl.create_default_context()

    result: Dict[str, Any] = {
        "domain": normalized,
        "url": target_url,
        "scan_timestamp": timestamp,
        "present": False,
        "status": "unknown",
        "status_code": None,
        "content_type": None,
        "parsed_fields": {},
        "content_preview": None,
        "truncated": False,
    }

    try:
        with urllib.request.urlopen(req, timeout=DEFAULT_HTTP_TIMEOUT, context=ctx) as resp:
            result["status_code"] = getattr(resp, "status", 200)
            result["final_url"] = resp.geturl()
            result["content_type"] = resp.headers.get("Content-Type")
            raw_bytes = resp.read(MAX_SECURITY_TXT_BYTES + 1)
            byte_truncated = len(raw_bytes) > MAX_SECURITY_TXT_BYTES
            text = raw_bytes[:MAX_SECURITY_TXT_BYTES].decode("utf-8", errors="replace")

            result["present"] = True
            result["status"] = "found"
            result["parsed_fields"] = _parse_security_txt_fields(text)
            result["truncated"] = byte_truncated or (len(text) > MAX_SECURITY_TXT_PREVIEW_CHARS)
            result["content_preview"] = text[:MAX_SECURITY_TXT_PREVIEW_CHARS]
    except urllib.error.HTTPError as e:
        result["status_code"] = e.code
        if e.code == 404:
            result["status"] = "not_found"
            result["message"] = "security.txt not found (HTTP 404)."
        else:
            result["status"] = "http_error"
            result["error"] = f"HTTP Error {e.code}: {e.reason}"
    except urllib.error.URLError as e:
        result["status"] = "connection_error"
        result["error"] = f"Connection failed: {e.reason}"
    except Exception as e:
        result["status"] = "connection_error"
        result["error"] = f"Request failed: {str(e)}"

    return result


# ============================================================================
# MCP Tool Registry Definitions
# ============================================================================

def get_tools_definition() -> List[Dict[str, Any]]:
    """Returns the MCP tool definitions for tools/list."""
    return [
        {
            "name": "check_dns_records",
            "description": "Passively queries A, AAAA, MX, NS, and CAA DNS records for a domain and returns DNS security posture observations.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target domain or URL (normalized automatically, e.g. 'example.com' or 'https://example.com/path').",
                    }
                },
                "required": ["domain"],
            },
        },
        {
            "name": "check_email_auth",
            "description": "Passively checks SPF (v=spf1), DMARC (_dmarc), and DKIM (<selector>._domainkey) TXT records and flags misconfigurations such as '+all' or 'p=none'.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target domain or URL to audit.",
                    },
                    "dkim_selectors": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional list of DKIM selectors to probe (defaults to ['default', 'google', 'selector1', 'selector2', 'k1']).",
                    },
                },
                "required": ["domain"],
            },
        },
        {
            "name": "check_security_txt",
            "description": "Safely fetches https://<domain>/.well-known/security.txt (RFC 9116) with bounded size and short timeout.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target domain or URL to check for security.txt.",
                    }
                },
                "required": ["domain"],
            },
        },
    ]


# ============================================================================
# MCP JSON-RPC 2.0 Dispatcher & Stdio Loop
# ============================================================================

def handle_json_rpc(request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Handles an incoming JSON-RPC 2.0 MCP request."""
    msg_id = request.get("id")
    method = request.get("method")
    params = request.get("params") or {}

    log_debug(f"Handling method: {method} (id: {msg_id})")

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
                    "version": SERVER_VERSION,
                },
            },
        }

    if method == "notifications/initialized":
        log_debug("MCP initialized notification acknowledged.")
        return None

    if method == "ping":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {},
        }

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "tools": get_tools_definition()
            },
        }

    if method == "tools/call":
        tool_name = params.get("name")
        args = params.get("arguments") or {}
        log_debug(f"Executing tool '{tool_name}' with args {args}")

        try:
            if tool_name == "check_dns_records":
                res_data = check_dns_records(domain=args.get("domain"))
            elif tool_name == "check_email_auth":
                res_data = check_email_auth(
                    domain=args.get("domain"),
                    dkim_selectors=args.get("dkim_selectors"),
                )
            elif tool_name == "check_security_txt":
                res_data = check_security_txt(domain=args.get("domain"))
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32601,
                        "message": f"Tool '{tool_name}' not found on server '{SERVER_NAME}'",
                    },
                }

            formatted_text = json.dumps(res_data, indent=2)
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": formatted_text,
                        }
                    ],
                    "isError": bool(res_data.get("error")),
                },
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
                            "text": json.dumps({"error": str(e)}, indent=2),
                        }
                    ],
                    "isError": True,
                },
            }

    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {
            "code": -32601,
            "message": f"Method '{method}' not implemented.",
        },
    }


def run_stdio_server() -> None:
    """Runs the MCP server over standard I/O."""
    log_debug("Starting MCP stdio server. Awaiting JSON-RPC requests...")

    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break

            line = line.strip()
            if not line:
                continue

            if line.startswith("Content-Length:"):
                content_len = int(line.split(":", 1)[1].strip())
                while True:
                    hdr = sys.stdin.readline().strip()
                    if not hdr:
                        break
                body = sys.stdin.read(content_len)
                request = json.loads(body)
            else:
                request = json.loads(line)

            response = handle_json_rpc(request)
            if response is not None:
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()

        except json.JSONDecodeError as e:
            log_debug(f"JSON decode error: {e}")
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "Parse error: invalid JSON"},
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
    parser = argparse.ArgumentParser(description="DNS & Email Posture Auditor MCP Server")
    parser.parse_args()
    run_stdio_server()
