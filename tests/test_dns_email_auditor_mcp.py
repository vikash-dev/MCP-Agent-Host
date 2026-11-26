"""
Unit and Integration Tests for servers/dns_email_auditor_mcp.py.
"""

import io
import json
import socket
import subprocess
import sys
import urllib.error
import pytest

from core.mcp_manager import MCPManager
from servers import dns_email_auditor_mcp as auditor


@pytest.fixture
def dns_mcp_config(tmp_path):
    cfg_data = {
        "servers": {
            "dns_email_auditor": {
                "name": "dns_email_auditor",
                "description": "DNS & Email Posture Auditor",
                "transport": "stdio",
                "command": sys.executable,
                "args": ["-u", "servers/dns_email_auditor_mcp.py"],
                "cwd": ".",
                "enabled": True,
                "requires_approval": False,
                "tools_require_approval": [],
            }
        }
    }
    cfg_file = tmp_path / "mcp_servers.json"
    cfg_file.write_text(json.dumps(cfg_data, indent=2), encoding="utf-8")
    return str(cfg_file)


def test_normalize_domain_variants():
    assert auditor.normalize_domain("Example.COM") == "example.com"
    assert auditor.normalize_domain("https://Example.COM/path/to/page/") == "example.com"
    assert auditor.normalize_domain("http://Sub.Example.COM:8443/login?a=1#frag") == "sub.example.com"
    assert auditor.normalize_domain("example.com:8080/foo/") == "example.com"
    assert auditor.normalize_domain("example.com.") == "example.com"
    assert auditor.normalize_domain("  localhost:5000/  ") == "localhost"


@pytest.mark.parametrize(
    "bad_input",
    ["", "   ", "bad domain.com", "https:///missing-host", "invalid_label!.example.com", None],
)
def test_normalize_domain_invalid_inputs(bad_input):
    with pytest.raises(ValueError):
        auditor.normalize_domain(bad_input)  # type: ignore[arg-type]

    res_dns = auditor.check_dns_records(bad_input)  # type: ignore[arg-type]
    assert "error" in res_dns

    res_mail = auditor.check_email_auth(bad_input)  # type: ignore[arg-type]
    assert "error" in res_mail

    res_sec = auditor.check_security_txt(bad_input)  # type: ignore[arg-type]
    assert "error" in res_sec
    assert res_sec.get("present") is False


def test_check_dns_records_socket_fallback(monkeypatch):
    monkeypatch.setattr(auditor, "HAS_DNSPYTHON", False)
    monkeypatch.setattr(auditor, "dns", None)

    def fake_getaddrinfo(host, port, family=0, type=0):
        assert host == "example.com"
        if family == socket.AF_INET:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
        raise socket.gaierror(11004, "No AAAA record")

    monkeypatch.setattr(auditor.socket, "getaddrinfo", fake_getaddrinfo)

    res = auditor.check_dns_records("https://Example.COM:443/index.html")
    assert res["domain"] == "example.com"
    assert res["records"]["A"]["status"] == "ok"
    assert res["records"]["A"]["values"] == ["93.184.216.34"]
    assert res["records"]["A"]["backend"] == "socket"
    assert res["records"]["AAAA"]["status"] == "not_found"
    assert res["records"]["MX"]["status"] == "unavailable"
    assert res["records"]["NS"]["status"] == "unavailable"
    assert res["records"]["CAA"]["status"] == "unavailable"
    assert len(res["posture_observations"]) >= 3


def test_check_dns_records_full_posture(monkeypatch):
    mock_map = {
        ("example.com", "A"): {"status": "ok", "values": ["93.184.216.34"], "backend": "dnspython"},
        ("example.com", "AAAA"): {"status": "ok", "values": ["2606:2800:220:1:248:1893:25c8:1946"], "backend": "dnspython"},
        ("example.com", "MX"): {"status": "ok", "values": [{"preference": 10, "exchange": "mail.example.com"}], "backend": "dnspython"},
        ("example.com", "NS"): {"status": "ok", "values": ["ns1.example.com"], "backend": "dnspython"},
        ("example.com", "CAA"): {"status": "not_found", "values": [], "backend": "dnspython"},
    }
    monkeypatch.setattr(auditor, "_query_dns_record", lambda q, r: mock_map[(q, r)])

    res = auditor.check_dns_records("example.com")
    assert res["records"]["MX"]["values"][0]["exchange"] == "mail.example.com"
    obs_text = " ".join(o["observation"] for o in res["posture_observations"])
    assert "Only 1 NS record" in obs_text
    assert "No CAA record found" in obs_text
    assert "MX records present" in obs_text


def test_check_email_auth_risky_spf_and_dmarc(monkeypatch):
    def fake_query(qname, rdtype):
        assert rdtype == "TXT"
        if qname == "example.com":
            return {"status": "ok", "values": ["v=spf1 include:_spf.example.com +all"], "backend": "dnspython"}
        if qname == "_dmarc.example.com":
            return {"status": "ok", "values": ["v=DMARC1; p=none; rua=mailto:dmarc@example.com"], "backend": "dnspython"}
        if qname == "google._domainkey.example.com":
            return {"status": "ok", "values": ["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"], "backend": "dnspython"}
        return {"status": "not_found", "values": [], "backend": "dnspython"}

    monkeypatch.setattr(auditor, "_query_dns_record", fake_query)

    res = auditor.check_email_auth("https://Example.COM/test")
    assert res["domain"] == "example.com"
    assert res["spf"]["present"] is True
    assert res["spf"]["has_risky_plus_all"] is True
    assert res["spf"]["all_mechanism"] == "+all"
    assert res["dmarc"]["present"] is True
    assert res["dmarc"]["policy"] == "none"
    assert res["dmarc"]["rua_configured"] is True
    assert len(res["dkim"]["found_selectors"]) == 1
    assert res["dkim"]["found_selectors"][0]["selector"] == "google"
    assert res["dkim"]["found_selectors"][0]["key_present"] is True
    assert any(f["control"] == "SPF" and f["severity"] == "HIGH" for f in res["findings"])
    assert any(f["control"] == "DMARC" and f["severity"] == "MEDIUM" for f in res["findings"])


def test_check_email_auth_unavailable_dnspython(monkeypatch):
    monkeypatch.setattr(auditor, "HAS_DNSPYTHON", False)
    monkeypatch.setattr(auditor, "dns", None)

    res = auditor.check_email_auth("example.com", dkim_selectors=["custom1"])
    assert "error" in res
    assert res["spf"]["status"] == "unavailable"
    assert res["dmarc"]["status"] == "unavailable"
    assert res["dkim"]["checked_selectors"] == ["custom1"]
    assert res["dkim"]["unavailable_count"] == 1


def test_check_security_txt_found_404_and_error(monkeypatch):
    class FakeResponse:
        def __init__(self, body: bytes):
            self.status = 200
            self._body = body
            self.headers = {"Content-Type": "text/plain; charset=utf-8"}

        def geturl(self):
            return "https://example.com/.well-known/security.txt"

        def read(self, n=-1):
            return self._body[:n] if n >= 0 else self._body

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    # 1. Found + capped response size
    huge_body = b"Contact: mailto:sec@example.com\nExpires: 2027-01-01T00:00:00Z\n" + (b"A" * 20000)
    monkeypatch.setattr(auditor.urllib.request, "urlopen", lambda req, timeout=5, context=None: FakeResponse(huge_body))
    res_ok = auditor.check_security_txt("https://Example.COM:8080/foo")
    assert res_ok["present"] is True
    assert res_ok["status"] == "found"
    assert res_ok["status_code"] == 200
    assert res_ok["truncated"] is True
    assert "sec@example.com" in res_ok["parsed_fields"]["Contact"][0]
    assert len(res_ok["content_preview"]) <= auditor.MAX_SECURITY_TXT_PREVIEW_CHARS

    # 2. HTTP 404
    def raise_404(req, timeout=5, context=None):
        raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, io.BytesIO(b""))

    monkeypatch.setattr(auditor.urllib.request, "urlopen", raise_404)
    res_404 = auditor.check_security_txt("example.com")
    assert res_404["present"] is False
    assert res_404["status"] == "not_found"
    assert res_404["status_code"] == 404

    # 3. Connection error
    def raise_conn(req, timeout=5, context=None):
        raise urllib.error.URLError("timed out")

    monkeypatch.setattr(auditor.urllib.request, "urlopen", raise_conn)
    res_err = auditor.check_security_txt("example.com")
    assert res_err["present"] is False
    assert res_err["status"] == "connection_error"
    assert "error" in res_err


def test_dns_auditor_stdio_protocol_strict_json():
    proc = subprocess.Popen(
        [sys.executable, "-u", "servers/dns_email_auditor_mcp.py"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    try:
        requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "check_dns_records", "arguments": {"domain": "http://LocalHost:8000/test"}},
            },
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "check_dns_records", "arguments": {"domain": "   "}},
            },
        ]
        for req in requests:
            proc.stdin.write(json.dumps(req) + "\n")
        proc.stdin.close()

        stdout_lines = [line.strip() for line in proc.stdout.read().splitlines() if line.strip()]
        assert len(stdout_lines) == 4  # notification emits no response
        parsed = [json.loads(line) for line in stdout_lines]
        assert parsed[0]["result"]["serverInfo"]["name"] == "dns_email_auditor"
        tool_names = [t["name"] for t in parsed[1]["result"]["tools"]]
        assert tool_names == ["check_dns_records", "check_email_auth", "check_security_txt"]

        call_ok = json.loads(parsed[2]["result"]["content"][0]["text"])
        assert call_ok["domain"] == "localhost"
        assert parsed[3]["result"]["isError"] is True
    finally:
        proc.kill()
        proc.wait(timeout=5)


@pytest.mark.asyncio
async def test_mcp_manager_dns_email_auditor(dns_mcp_config):
    manager = MCPManager(config_path=dns_mcp_config)
    await manager.initialize()
    try:
        tools = manager.get_all_tools()
        names = [t["name"] for t in tools]
        assert set(names) == {"check_dns_records", "check_email_auth", "check_security_txt"}

        raw = await manager.call_tool("check_dns_records", {"domain": "https://localhost:8080/health"})
        data = json.loads(raw)
        assert data["domain"] == "localhost"
        assert "records" in data
    finally:
        await manager.shutdown()
