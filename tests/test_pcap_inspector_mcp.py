"""
Unit and Integration Tests for servers/pcap_inspector_mcp.py
and config/mcp_servers.json server registration.
"""

import json
import os
import socket
import struct
import subprocess
import sys
import pytest

from core.mcp_manager import MCPManager
from servers import pcap_inspector_mcp as pcap_srv


# ============================================================================
# Synthetic PCAP / PCAPNG Packet Builders
# ============================================================================

def _ipv4_header(src_ip: str, dst_ip: str, proto: int, payload_len: int) -> bytes:
    total_len = 20 + payload_len
    return struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        1,
        0,
        64,
        proto,
        0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )


def _eth_ipv4_udp(src_ip: str, dst_ip: str, sport: int, dport: int, payload: bytes) -> bytes:
    eth = b"\xaa\xbb\xcc\xdd\xee\xff\x11\x22\x33\x44\x55\x66\x08\x00"
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    ip = _ipv4_header(src_ip, dst_ip, 17, len(udp) + len(payload))
    return eth + ip + udp + payload


def _eth_ipv4_tcp(src_ip: str, dst_ip: str, sport: int, dport: int, payload: bytes) -> bytes:
    eth = b"\xaa\xbb\xcc\xdd\xee\xff\x11\x22\x33\x44\x55\x66\x08\x00"
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 0x50, 0x18, 65535, 0, 0)
    ip = _ipv4_header(src_ip, dst_ip, 6, len(tcp) + len(payload))
    return eth + ip + tcp + payload


def _eth_ipv4_icmp(src_ip: str, dst_ip: str) -> bytes:
    eth = b"\xaa\xbb\xcc\xdd\xee\xff\x11\x22\x33\x44\x55\x66\x08\x00"
    icmp = struct.pack("!BBHI", 8, 0, 0, 1) + b"ping"
    ip = _ipv4_header(src_ip, dst_ip, 1, len(icmp))
    return eth + ip + icmp


def _dns_query_payload(domain: str) -> bytes:
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in domain.split(".")) + b"\x00"
    return header + qname + struct.pack("!HH", 1, 1)


def _tls_client_hello(sni: str) -> bytes:
    sni_bytes = sni.encode("ascii")
    sni_entry = struct.pack("!BH", 0, len(sni_bytes)) + sni_bytes
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list
    extensions = struct.pack("!H", len(ext)) + ext
    body = (
        b"\x03\x03"
        + (b"\x11" * 32)
        + b"\x00"
        + struct.pack("!HH", 2, 0x1301)
        + b"\x01\x00"
        + extensions
    )
    hs = struct.pack("!B", 1) + len(body).to_bytes(3, "big") + body
    return struct.pack("!BHH", 0x16, 0x0301, len(hs)) + hs


def _write_pcap(path, frames_with_ts):
    global_hdr = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    chunks = [global_hdr]
    for ts_sec, ts_usec, frame in frames_with_ts:
        chunks.append(struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame)))
        chunks.append(frame)
    path.write_bytes(b"".join(chunks))


def _pcapng_block(block_type: int, body: bytes) -> bytes:
    pad = (-len(body)) % 4
    padded = body + (b"\x00" * pad)
    total_len = 12 + len(padded)
    return struct.pack("<II", block_type, total_len) + padded + struct.pack("<I", total_len)


def _write_pcapng(path, frames_with_ts):
    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    idb_body = struct.pack("<HHI", 1, 0, 65535)
    chunks = [_pcapng_block(0x0A0D0D0A, shb_body), _pcapng_block(0x00000001, idb_body)]
    for ts_sec, ts_usec, frame in frames_with_ts:
        ts_us = ts_sec * 1_000_000 + ts_usec
        epb_body = (
            struct.pack("<IIIII", 0, ts_us >> 32, ts_us & 0xFFFFFFFF, len(frame), len(frame))
            + frame
        )
        chunks.append(_pcapng_block(0x00000006, epb_body))
    path.write_bytes(b"".join(chunks))


@pytest.fixture
def sample_pcap(tmp_path):
    pcap_path = tmp_path / "sample.pcap"
    frames = [
        (1700000000, 0, _eth_ipv4_udp("192.168.1.10", "8.8.8.8", 53000, 53, _dns_query_payload("example.com"))),
        (1700000001, 500000, _eth_ipv4_udp("192.168.1.10", "8.8.8.8", 53001, 53, _dns_query_payload("example.com"))),
        (1700000002, 0, _eth_ipv4_udp("192.168.1.11", "8.8.8.8", 53002, 53, _dns_query_payload("api.example.com"))),
        (1700000003, 0, _eth_ipv4_tcp("192.168.1.10", "93.184.216.34", 44000, 80, b"GET / HTTP/1.1\r\nHost: web.example.com\r\n\r\n")),
        (1700000004, 0, _eth_ipv4_tcp("192.168.1.10", "93.184.216.34", 44001, 443, _tls_client_hello("secure.example.com"))),
        (1700000005, 0, _eth_ipv4_icmp("10.0.0.5", "10.0.0.1")),
    ]
    _write_pcap(pcap_path, frames)
    return str(pcap_path)


@pytest.fixture
def sample_pcapng(tmp_path):
    pcapng_path = tmp_path / "sample.pcapng"
    frames = [
        (1700000100, 0, _eth_ipv4_udp("10.1.1.2", "1.1.1.1", 51000, 53, _dns_query_payload("test.corp"))),
        (1700000102, 250000, _eth_ipv4_tcp("10.1.1.2", "10.1.1.50", 51001, 443, _tls_client_hello("portal.test.corp"))),
    ]
    _write_pcapng(pcapng_path, frames)
    return str(pcapng_path)


# ============================================================================
# Validation & Error-Handling Tests
# ============================================================================

def test_pcap_validation_rejects_invalid_paths_and_extensions(tmp_path, monkeypatch):
    # Non-existent file
    res_missing = pcap_srv.summarize_pcap(str(tmp_path / "missing.pcap"))
    assert "error" in res_missing

    # Directory instead of regular file
    res_dir = pcap_srv.summarize_pcap(str(tmp_path))
    assert "error" in res_dir

    # Invalid extension
    bad_ext = tmp_path / "notes.txt"
    bad_ext.write_text("not a pcap", encoding="utf-8")
    res_ext = pcap_srv.extract_dns_and_http_hosts(str(bad_ext))
    assert "Unsupported file extension" in res_ext["error"]

    # Empty .pcap file
    empty_pcap = tmp_path / "empty.pcap"
    empty_pcap.write_bytes(b"")
    res_empty = pcap_srv.filter_pcap_packets(str(empty_pcap))
    assert "empty" in res_empty["error"].lower()

    # Oversized file check
    big_pcap = tmp_path / "big.pcap"
    big_pcap.write_bytes(b"A" * 200)
    monkeypatch.setenv("PCAP_MAX_FILE_SIZE_BYTES", "100")
    res_big = pcap_srv.summarize_pcap(str(big_pcap))
    assert "exceeds safety limit" in res_big["error"]


def test_pcap_missing_backend_returns_actionable_error(sample_pcap, monkeypatch):
    monkeypatch.setenv("PCAP_DISABLE_BUILTIN_PARSER", "1")
    monkeypatch.setattr(pcap_srv.shutil, "which", lambda name: None)
    monkeypatch.setattr(pcap_srv, "HAS_DPKT", False)
    monkeypatch.setattr(pcap_srv, "dpkt", None)

    res = pcap_srv.summarize_pcap(sample_pcap)
    assert "error" in res
    assert "tshark" in res["error"].lower()


# ============================================================================
# Functional & Bounding Tests
# ============================================================================

def test_summarize_pcap_and_top_ip_cap(tmp_path, sample_pcap, sample_pcapng):
    res = pcap_srv.summarize_pcap(sample_pcap)
    assert "error" not in res
    assert res["total_packets"] == 6
    assert res["time_span"]["duration_seconds"] == pytest.approx(5.0, abs=1e-4)
    assert res["protocol_counts"]["DNS"] == 3
    assert res["protocol_counts"]["HTTP"] == 1
    assert res["protocol_counts"]["TLS"] == 1
    assert res["protocol_counts"]["ICMP"] == 1
    assert res["top_source_ips"][0]["ip"] == "192.168.1.10"

    # Also verify .pcapng support
    res_ng = pcap_srv.summarize_pcap(sample_pcapng)
    assert "error" not in res_ng
    assert res_ng["total_packets"] == 2
    assert res_ng["protocol_counts"]["DNS"] == 1
    assert res_ng["protocol_counts"]["TLS"] == 1

    # Verify top source/destination IPs are capped to 10
    many_ips_pcap = tmp_path / "many_ips.pcap"
    many_frames = [
        (1700000000 + i, 0, _eth_ipv4_icmp(f"10.0.0.{i + 1}", f"10.0.1.{i + 1}"))
        for i in range(15)
    ]
    _write_pcap(many_ips_pcap, many_frames)
    res_many = pcap_srv.summarize_pcap(str(many_ips_pcap))
    assert res_many["total_packets"] == 15
    assert len(res_many["top_source_ips"]) == 10
    assert len(res_many["top_destination_ips"]) == 10


def test_extract_dns_and_http_hosts_dedup_and_limit(sample_pcap):
    res = pcap_srv.extract_dns_and_http_hosts(sample_pcap, limit=50)
    assert "error" not in res
    assert res["dns_queries"] == ["example.com", "api.example.com"]
    assert res["dns_queries_total_unique"] == 2
    assert res["http_hosts"] == ["web.example.com"]
    assert res["tls_sni_hosts"] == ["secure.example.com"]
    assert res["truncated"] is False

    # Enforce limit=1
    res_limited = pcap_srv.extract_dns_and_http_hosts(sample_pcap, limit=1)
    assert len(res_limited["dns_queries"]) == 1
    assert res_limited["dns_queries_total_unique"] == 2
    assert res_limited["truncated"] is True


def test_filter_pcap_packets(sample_pcap):
    res_dns = pcap_srv.filter_pcap_packets(sample_pcap, protocol="DNS", limit=2)
    assert res_dns["total_matches"] == 3
    assert res_dns["returned_count"] == 2
    assert res_dns["truncated"] is True
    assert all(p["protocol"] == "DNS" for p in res_dns["packets"])

    res_ip = pcap_srv.filter_pcap_packets(sample_pcap, ip_filter="10.0.0.5")
    assert res_ip["total_matches"] == 1
    assert res_ip["packets"][0]["protocol"] == "ICMP"

    res_cidr = pcap_srv.filter_pcap_packets(sample_pcap, ip_filter="192.168.1.0/24", protocol="TCP")
    assert res_cidr["total_matches"] == 2

    res_bad_ip = pcap_srv.filter_pcap_packets(sample_pcap, ip_filter="not-an-ip")
    assert "error" in res_bad_ip


# ============================================================================
# Stdio JSON-RPC & Registry Integration Tests
# ============================================================================

def test_pcap_inspector_stdio_protocol_strict_json(sample_pcap):
    proc = subprocess.Popen(
        [sys.executable, "-u", "servers/pcap_inspector_mcp.py"],
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
                "params": {"name": "summarize_pcap", "arguments": {"file_path": sample_pcap}},
            },
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "summarize_pcap", "arguments": {"file_path": "bad.exe"}},
            },
        ]
        for req in requests:
            proc.stdin.write(json.dumps(req) + "\n")
        proc.stdin.close()

        stdout_lines = [line.strip() for line in proc.stdout.read().splitlines() if line.strip()]
        assert len(stdout_lines) == 4
        parsed = [json.loads(line) for line in stdout_lines]
        assert parsed[0]["result"]["serverInfo"]["name"] == "pcap_inspector"
        tool_names = [t["name"] for t in parsed[1]["result"]["tools"]]
        assert tool_names == ["summarize_pcap", "extract_dns_and_http_hosts", "filter_pcap_packets"]

        summary = json.loads(parsed[2]["result"]["content"][0]["text"])
        assert summary["total_packets"] == 6
        assert parsed[3]["result"]["isError"] is True
    finally:
        proc.kill()
        proc.wait(timeout=5)


@pytest.mark.asyncio
async def test_mcp_manager_with_new_servers_and_config(tmp_path, sample_pcap):
    # Verify real config/mcp_servers.json contains both new servers with expected flags
    with open("config/mcp_servers.json", "r", encoding="utf-8") as f:
        real_cfg = json.load(f)
    servers_cfg = real_cfg["servers"]
    assert "dns_email_auditor" in servers_cfg
    assert "pcap_inspector" in servers_cfg
    assert servers_cfg["dns_email_auditor"]["enabled"] is True
    assert servers_cfg["dns_email_auditor"]["requires_approval"] is False
    assert servers_cfg["pcap_inspector"]["enabled"] is True
    assert servers_cfg["pcap_inspector"]["requires_approval"] is False

    # Copy config to tmp_path so toggling doesn't mutate repo config
    temp_cfg = tmp_path / "mcp_servers.json"
    temp_cfg.write_text(json.dumps(real_cfg, indent=2), encoding="utf-8")

    manager = MCPManager(config_path=str(temp_cfg))
    await manager.initialize()
    try:
        tools = {t["name"] for t in manager.get_all_tools()}
        assert {"check_dns_records", "check_email_auth", "check_security_txt"}.issubset(tools)
        assert {"summarize_pcap", "extract_dns_and_http_hosts", "filter_pcap_packets"}.issubset(tools)

        raw = await manager.call_tool("extract_dns_and_http_hosts", {"file_path": sample_pcap})
        data = json.loads(raw)
        assert "example.com" in data["dns_queries"]

        # Verify toggle disable/enable works cleanly
        assert await manager.disable_server("pcap_inspector")
        assert "pcap_inspector" not in manager.clients
        assert await manager.enable_server("pcap_inspector")
        assert "pcap_inspector" in manager.clients
    finally:
        await manager.shutdown()
