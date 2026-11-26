#!/usr/bin/env python3
"""
Local Packet Capture Inspector MCP Server
-----------------------------------------
Safe, read-only MCP server for inspecting local .pcap and .pcapng capture files.
Validates file existence, extension, and maximum file size before parsing.
Supports tshark (if installed on PATH), optional dpkt, and a built-in pure-Python
pcap/pcapng parser so basic inspection works without external dependencies.

Tools:
  - summarize_pcap: File size, packet count, time span, protocol counts, top IPs.
  - extract_dns_and_http_hosts: Deduplicated DNS queries, HTTP Host, and TLS SNI values.
  - filter_pcap_packets: Bounded packet summaries filtered by protocol and/or IP/CIDR.

Standard stdio transport:
  - Reads JSON-RPC 2.0 requests from stdin.
  - Writes newline-delimited JSON-RPC 2.0 responses to stdout.
  - Diagnostic logs are directed strictly to stderr.
"""

import argparse
import datetime
import ipaddress
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

try:
    import dpkt  # type: ignore[import-not-found]
    HAS_DPKT = True
except ImportError:
    dpkt = None
    HAS_DPKT = False

# Server Metadata
SERVER_NAME = "pcap_inspector"
SERVER_VERSION = "1.0.0"
PROTOCOL_VERSION = "2024-11-05"

DEFAULT_MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB
VALID_EXTENSIONS = (".pcap", ".pcapng")
MAX_TOP_IPS = 10
MAX_PROTOCOL_BUCKETS = 25
DEFAULT_HOST_LIMIT = 50
MAX_HOST_LIMIT = 200
DEFAULT_PACKET_LIMIT = 25
MAX_PACKET_LIMIT = 100
TSHARK_TIMEOUT_SECONDS = 20

_HTTP_PREFIXES = (
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
    b"HTTP/1.",
)

_IP_PROTO_NAMES = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    132: "SCTP",
}


def log_debug(message: str) -> None:
    """Write debug output to stderr without polluting stdout."""
    sys.stderr.write(f"[{SERVER_NAME}] {message}\n")
    sys.stderr.flush()


def get_max_file_size_bytes() -> int:
    """Returns the configured max capture file size limit in bytes."""
    raw_bytes = os.environ.get("PCAP_MAX_FILE_SIZE_BYTES")
    if raw_bytes:
        try:
            val = int(raw_bytes)
            if val > 0:
                return val
        except ValueError:
            pass

    raw_mb = os.environ.get("PCAP_MAX_FILE_SIZE_MB")
    if raw_mb:
        try:
            val_mb = float(raw_mb)
            if val_mb > 0:
                return int(val_mb * 1024 * 1024)
        except ValueError:
            pass

    return DEFAULT_MAX_FILE_SIZE_BYTES


def _validate_pcap_path(file_path: Any) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """Validates existence, regular file type, .pcap/.pcapng extension, and size limit."""
    if not isinstance(file_path, str) or not file_path.strip():
        return None, {
            "file_path": file_path,
            "error": "Invalid file_path: must be a non-empty string.",
        }

    raw = file_path.strip()
    abs_path = os.path.abspath(raw)

    if not os.path.exists(abs_path):
        return None, {
            "file_path": raw,
            "error": f"Capture file not found: '{raw}'.",
        }

    if not os.path.isfile(abs_path):
        return None, {
            "file_path": raw,
            "error": f"Path is not a regular file: '{raw}'.",
        }

    ext = os.path.splitext(abs_path)[1].lower()
    if ext not in VALID_EXTENSIONS:
        return None, {
            "file_path": raw,
            "error": f"Unsupported file extension '{ext or '(none)'}'. Only .pcap and .pcapng files are supported.",
        }

    file_size = os.path.getsize(abs_path)
    if file_size == 0:
        return None, {
            "file_path": abs_path,
            "file_size_bytes": 0,
            "error": f"Capture file '{raw}' is empty (0 bytes).",
        }

    max_bytes = get_max_file_size_bytes()
    if file_size > max_bytes:
        return None, {
            "file_path": abs_path,
            "file_size_bytes": file_size,
            "max_file_size_bytes": max_bytes,
            "error": (
                f"Capture file size ({file_size} bytes) exceeds safety limit of "
                f"{max_bytes} bytes ({max_bytes / (1024 * 1024):.1f} MB)."
            ),
        }

    return abs_path, None


# ============================================================================
# Packet Dissection Helpers (Pure-Python Fallback)
# ============================================================================

def _parse_dns_qname(payload: bytes, offset: int) -> Tuple[Optional[str], int]:
    """Parses a DNS QNAME from a DNS message payload with compression pointer loop protection."""
    labels: List[str] = []
    visited = set()
    cur = offset
    jumped = False
    next_offset = offset

    for _ in range(64):
        if cur >= len(payload) or cur in visited:
            return None, cur
        visited.add(cur)
        length = payload[cur]
        if length == 0:
            if not jumped:
                next_offset = cur + 1
            break
        if (length & 0xC0) == 0xC0:
            if cur + 1 >= len(payload):
                return None, cur
            ptr = ((length & 0x3F) << 8) | payload[cur + 1]
            if not jumped:
                next_offset = cur + 2
                jumped = True
            cur = ptr
            continue
        if length > 63 or cur + 1 + length > len(payload):
            return None, cur
        label_bytes = payload[cur + 1 : cur + 1 + length]
        labels.append(label_bytes.decode("ascii", errors="replace"))
        cur += 1 + length
    else:
        return None, cur

    name = ".".join(labels).strip(".").lower()
    return (name if name else None), next_offset


def _extract_dns_queries(dns_payload: bytes) -> List[str]:
    """Extracts queried domain names from a DNS packet payload."""
    if len(dns_payload) < 12:
        return []
    qdcount = struct.unpack("!H", dns_payload[4:6])[0]
    if qdcount == 0 or qdcount > 32:
        return []

    queries: List[str] = []
    offset = 12
    for _ in range(qdcount):
        qname, next_off = _parse_dns_qname(dns_payload, offset)
        if not qname or next_off + 4 > len(dns_payload):
            break
        queries.append(qname)
        offset = next_off + 4  # QTYPE (2) + QCLASS (2)
    return queries


def _extract_http_host(tcp_payload: bytes) -> Optional[str]:
    """Extracts the HTTP Host header from a cleartext HTTP request."""
    if not tcp_payload or not tcp_payload.startswith(_HTTP_PREFIXES):
        return None
    head = tcp_payload[:4096].decode("latin-1", errors="replace")
    for line in head.splitlines()[1:]:
        if not line.strip():
            break
        if line.lower().startswith("host:"):
            host_val = line.split(":", 1)[1].strip()
            return host_val[:255] if host_val else None
    return None


def _extract_tls_sni(tcp_payload: bytes) -> Optional[str]:
    """Extracts SNI hostname from a TLS ClientHello record."""
    # TLS Record: ContentType=0x16 (Handshake), Version=0x03xx, Length (2)
    if len(tcp_payload) < 43:
        return None
    if tcp_payload[0] != 0x16 or tcp_payload[1] != 0x03:
        return None
    # Handshake header starts at offset 5: HandshakeType=0x01 (ClientHello)
    if tcp_payload[5] != 0x01:
        return None

    pos = 5 + 4  # Skip handshake header (type + 3-byte len)
    pos += 2 + 32  # Skip client_version + random
    if pos >= len(tcp_payload):
        return None

    session_id_len = tcp_payload[pos]
    pos += 1 + session_id_len
    if pos + 2 > len(tcp_payload):
        return None

    cipher_suites_len = struct.unpack("!H", tcp_payload[pos : pos + 2])[0]
    pos += 2 + cipher_suites_len
    if pos + 1 > len(tcp_payload):
        return None

    comp_methods_len = tcp_payload[pos]
    pos += 1 + comp_methods_len
    if pos + 2 > len(tcp_payload):
        return None

    extensions_len = struct.unpack("!H", tcp_payload[pos : pos + 2])[0]
    pos += 2
    ext_end = min(len(tcp_payload), pos + extensions_len)

    while pos + 4 <= ext_end:
        ext_type, ext_len = struct.unpack("!HH", tcp_payload[pos : pos + 4])
        pos += 4
        if pos + ext_len > ext_end:
            break
        if ext_type == 0x0000 and ext_len >= 5:  # server_name
            list_len = struct.unpack("!H", tcp_payload[pos : pos + 2])[0]
            s_pos = pos + 2
            s_end = min(pos + ext_len, s_pos + list_len)
            while s_pos + 3 <= s_end:
                name_type = tcp_payload[s_pos]
                name_len = struct.unpack("!H", tcp_payload[s_pos + 1 : s_pos + 3])[0]
                s_pos += 3
                if s_pos + name_len > s_end:
                    break
                if name_type == 0:
                    return tcp_payload[s_pos : s_pos + name_len].decode("ascii", errors="replace").lower()
                s_pos += name_len
        pos += ext_len

    return None


def _decode_l2_l3_l4(raw: bytes, link_type: int) -> Dict[str, Any]:
    """Dissects L2/L3/L4/L7 metadata from raw frame bytes."""
    info: Dict[str, Any] = {
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "protocol": "UNKNOWN",
        "dns_queries": [],
        "http_host": None,
        "tls_sni": None,
        "summary": "",
    }

    ethertype: Optional[int] = None
    l3_offset = 0

    if link_type == 1:  # Ethernet
        if len(raw) < 14:
            info["protocol"] = "FRAME"
            return info
        ethertype = struct.unpack("!H", raw[12:14])[0]
        l3_offset = 14
        # Handle 802.1Q / 802.1ad VLAN tags
        while ethertype in (0x8100, 0x88A8) and len(raw) >= l3_offset + 4:
            ethertype = struct.unpack("!H", raw[l3_offset + 2 : l3_offset + 4])[0]
            l3_offset += 4
    elif link_type == 113:  # Linux cooked capture (SLL)
        if len(raw) < 16:
            info["protocol"] = "FRAME"
            return info
        ethertype = struct.unpack("!H", raw[14:16])[0]
        l3_offset = 16
    elif link_type in (101, 228, 229):  # Raw IP / IPv4 / IPv6
        if not raw:
            return info
        version = (raw[0] >> 4) & 0x0F
        ethertype = 0x0800 if version == 4 else (0x86DD if version == 6 else None)
        l3_offset = 0
    else:
        info["protocol"] = f"LINKTYPE_{link_type}"
        info["summary"] = f"Frame len={len(raw)} linktype={link_type}"
        return info

    if ethertype == 0x0806:
        info["protocol"] = "ARP"
        info["summary"] = f"ARP len={len(raw)}"
        return info

    l4_proto: Optional[int] = None
    l4_offset = l3_offset

    if ethertype == 0x0800 and len(raw) >= l3_offset + 20:
        ver_ihl = raw[l3_offset]
        ihl = (ver_ihl & 0x0F) * 4
        if ihl < 20 or len(raw) < l3_offset + ihl:
            info["protocol"] = "IPv4"
            return info
        l4_proto = raw[l3_offset + 9]
        info["src_ip"] = socket.inet_ntoa(raw[l3_offset + 12 : l3_offset + 16])
        info["dst_ip"] = socket.inet_ntoa(raw[l3_offset + 16 : l3_offset + 20])
        l4_offset = l3_offset + ihl
        info["protocol"] = _IP_PROTO_NAMES.get(l4_proto, f"IP_{l4_proto}")
    elif ethertype == 0x86DD and len(raw) >= l3_offset + 40:
        l4_proto = raw[l3_offset + 6]
        info["src_ip"] = socket.inet_ntop(socket.AF_INET6, raw[l3_offset + 8 : l3_offset + 24])
        info["dst_ip"] = socket.inet_ntop(socket.AF_INET6, raw[l3_offset + 24 : l3_offset + 40])
        l4_offset = l3_offset + 40
        info["protocol"] = _IP_PROTO_NAMES.get(l4_proto, f"IPv6_{l4_proto}")
    else:
        info["protocol"] = f"ETH_0x{ethertype:04X}" if ethertype is not None else "UNKNOWN"
        info["summary"] = f"{info['protocol']} len={len(raw)}"
        return info

    app_payload = b""
    if l4_proto == 6 and len(raw) >= l4_offset + 20:  # TCP
        src_port, dst_port = struct.unpack("!HH", raw[l4_offset : l4_offset + 4])
        data_offset = ((raw[l4_offset + 12] >> 4) & 0x0F) * 4
        data_offset = max(20, data_offset)
        info["src_port"] = src_port
        info["dst_port"] = dst_port
        app_payload = raw[l4_offset + data_offset :]
        info["protocol"] = "TCP"

        if app_payload:
            if (src_port == 53 or dst_port == 53) and len(app_payload) > 2:
                dns_len = struct.unpack("!H", app_payload[:2])[0]
                dns_queries = _extract_dns_queries(app_payload[2 : 2 + dns_len])
                if dns_queries:
                    info["protocol"] = "DNS"
                    info["dns_queries"] = dns_queries
            if info["protocol"] == "TCP":
                http_host = _extract_http_host(app_payload)
                if http_host or app_payload.startswith(b"HTTP/1."):
                    info["protocol"] = "HTTP"
                    info["http_host"] = http_host
                else:
                    sni = _extract_tls_sni(app_payload)
                    if sni:
                        info["protocol"] = "TLS"
                        info["tls_sni"] = sni
                    elif app_payload[0] in (0x14, 0x15, 0x16, 0x17) and len(app_payload) >= 5 and app_payload[1] == 0x03:
                        info["protocol"] = "TLS"

    elif l4_proto == 17 and len(raw) >= l4_offset + 8:  # UDP
        src_port, dst_port = struct.unpack("!HH", raw[l4_offset : l4_offset + 4])
        info["src_port"] = src_port
        info["dst_port"] = dst_port
        app_payload = raw[l4_offset + 8 :]
        info["protocol"] = "UDP"

        if src_port == 53 or dst_port == 53 or src_port == 5353 or dst_port == 5353:
            dns_queries = _extract_dns_queries(app_payload)
            info["protocol"] = "MDNS" if (src_port == 5353 or dst_port == 5353) else "DNS"
            info["dns_queries"] = dns_queries

    src_disp = f"{info['src_ip']}:{info['src_port']}" if info["src_port"] is not None else (info["src_ip"] or "unknown")
    dst_disp = f"{info['dst_ip']}:{info['dst_port']}" if info["dst_port"] is not None else (info["dst_ip"] or "unknown")

    extra = ""
    if info["dns_queries"]:
        extra = f" (DNS query: {info['dns_queries'][0]})"
    elif info["http_host"]:
        extra = f" (HTTP Host: {info['http_host']})"
    elif info["tls_sni"]:
        extra = f" (TLS SNI: {info['tls_sni']})"

    info["summary"] = f"{info['protocol']} {src_disp} -> {dst_disp} len={len(raw)}{extra}"
    return info


def _parse_pcap_builtin(abs_path: str) -> List[Dict[str, Any]]:
    """Pure-Python parser for classic .pcap and .pcapng files."""
    with open(abs_path, "rb") as f:
        data = f.read()

    if len(data) < 24:
        raise ValueError("File is too small to be a valid .pcap or .pcapng capture.")

    magic4 = data[:4]
    packets: List[Dict[str, Any]] = []

    # 1. Classic libpcap
    pcap_magics = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000.0),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000.0),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000.0),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000.0),
    }
    if magic4 in pcap_magics:
        endian, ts_div = pcap_magics[magic4]
        _, _, _, _, _, _, link_type = struct.unpack(f"{endian}IHHIIII", data[:24])
        offset = 24
        idx = 0
        while offset + 16 <= len(data):
            ts_sec, ts_sub, incl_len, orig_len = struct.unpack(f"{endian}IIII", data[offset : offset + 16])
            offset += 16
            if offset + incl_len > len(data):
                break
            pkt_bytes = data[offset : offset + incl_len]
            offset += incl_len
            idx += 1
            decoded = _decode_l2_l3_l4(pkt_bytes, link_type)
            decoded["index"] = idx
            decoded["timestamp"] = ts_sec + (ts_sub / ts_div)
            decoded["length"] = orig_len or incl_len
            packets.append(decoded)
        return packets

    # 2. PCAPNG (Section Header Block 0x0A0D0D0A)
    if magic4 == b"\x0a\x0d\x0d\x0a":
        if len(data) < 28:
            raise ValueError("Truncated pcapng Section Header Block.")
        bom = data[8:12]
        if bom == b"\x4d\x3c\x2b\x1a":
            endian = "<"
        elif bom == b"\x1a\x2b\x3c\x4d":
            endian = ">"
        else:
            raise ValueError("Invalid pcapng byte-order magic.")

        interfaces: List[Tuple[int, float]] = []
        offset = 0
        idx = 0
        while offset + 12 <= len(data):
            btype, blen = struct.unpack(f"{endian}II", data[offset : offset + 8])
            if blen < 12 or offset + blen > len(data):
                break
            body = data[offset + 8 : offset + blen - 4]
            offset += blen

            if btype == 0x0A0D0D0A:
                # Reset interfaces per section if needed
                if len(body) >= 4:
                    sec_bom = body[0:4]
                    if sec_bom == b"\x4d\x3c\x2b\x1a":
                        endian = "<"
                    elif sec_bom == b"\x1a\x2b\x3c\x4d":
                        endian = ">"
                interfaces = []
            elif btype == 0x00000001 and len(body) >= 8:  # IDB
                link_type = struct.unpack(f"{endian}H", body[0:2])[0]
                ts_resol = 1e-6
                opt_off = 8
                while opt_off + 4 <= len(body):
                    opt_code, opt_len = struct.unpack(f"{endian}HH", body[opt_off : opt_off + 4])
                    opt_off += 4
                    if opt_code == 0:
                        break
                    padded_len = (opt_len + 3) & ~3
                    if opt_off + padded_len > len(body):
                        break
                    if opt_code == 9 and opt_len >= 1:
                        val = body[opt_off]
                        ts_resol = (2.0 ** -(val & 0x7F)) if (val & 0x80) else (10.0 ** -val)
                    opt_off += padded_len
                interfaces.append((link_type, ts_resol))
            elif btype == 0x00000006 and len(body) >= 20:  # EPB
                iface_id, ts_hi, ts_lo, cap_len, orig_len = struct.unpack(f"{endian}IIIII", body[:20])
                pkt_bytes = body[20 : 20 + cap_len]
                link_type, ts_resol = interfaces[iface_id] if iface_id < len(interfaces) else (1, 1e-6)
                idx += 1
                decoded = _decode_l2_l3_l4(pkt_bytes, link_type)
                decoded["index"] = idx
                decoded["timestamp"] = ((ts_hi << 32) | ts_lo) * ts_resol
                decoded["length"] = orig_len or cap_len
                packets.append(decoded)
            elif btype == 0x00000003 and len(body) >= 4:  # SPB
                orig_len = struct.unpack(f"{endian}I", body[:4])[0]
                pkt_bytes = body[4:]
                link_type = interfaces[0][0] if interfaces else 1
                idx += 1
                decoded = _decode_l2_l3_l4(pkt_bytes, link_type)
                decoded["index"] = idx
                decoded["timestamp"] = None
                decoded["length"] = orig_len or len(pkt_bytes)
                packets.append(decoded)
        return packets

    raise ValueError("Unrecognized capture magic header (expected .pcap or .pcapng).")


def _parse_with_tshark(tshark_bin: str, abs_path: str) -> List[Dict[str, Any]]:
    """Parses packets using tshark CLI into normalized packet records."""
    cmd = [
        tshark_bin,
        "-r",
        abs_path,
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-e",
        "frame.number",
        "-e",
        "frame.time_epoch",
        "-e",
        "frame.len",
        "-e",
        "ip.src",
        "-e",
        "ipv6.src",
        "-e",
        "ip.dst",
        "-e",
        "ipv6.dst",
        "-e",
        "tcp.srcport",
        "-e",
        "udp.srcport",
        "-e",
        "tcp.dstport",
        "-e",
        "udp.dstport",
        "-e",
        "_ws.col.Protocol",
        "-e",
        "dns.qry.name",
        "-e",
        "http.host",
        "-e",
        "tls.handshake.extensions_server_name",
    ]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=TSHARK_TIMEOUT_SECONDS,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"tshark exited with code {proc.returncode}")

    packets: List[Dict[str, Any]] = []
    for line_idx, raw_line in enumerate(proc.stdout.splitlines(), start=1):
        if not raw_line.strip():
            continue
        cols = raw_line.split("\t")
        cols += [""] * max(0, 15 - len(cols))
        (
            frame_no,
            ts_str,
            len_str,
            ip4_src,
            ip6_src,
            ip4_dst,
            ip6_dst,
            tcp_sport,
            udp_sport,
            tcp_dport,
            udp_dport,
            proto,
            dns_qry,
            http_host,
            tls_sni,
        ) = cols[:15]

        src_ip = ip4_src.split(",")[0] or ip6_src.split(",")[0] or None
        dst_ip = ip4_dst.split(",")[0] or ip6_dst.split(",")[0] or None
        src_port_str = tcp_sport or udp_sport
        dst_port_str = tcp_dport or udp_dport
        src_port = int(src_port_str.split(",")[0]) if src_port_str else None
        dst_port = int(dst_port_str.split(",")[0]) if dst_port_str else None
        dns_queries = [q.strip().lower() for q in dns_qry.split(",") if q.strip()]

        ts_val = float(ts_str) if ts_str else None
        pkt_len = int(len_str) if len_str.isdigit() else 0
        pkt_idx = int(frame_no) if frame_no.isdigit() else line_idx
        proto_clean = proto.strip() or "UNKNOWN"

        src_disp = f"{src_ip}:{src_port}" if src_port is not None else (src_ip or "unknown")
        dst_disp = f"{dst_ip}:{dst_port}" if dst_port is not None else (dst_ip or "unknown")
        summary = f"{proto_clean} {src_disp} -> {dst_disp} len={pkt_len}"
        if dns_queries:
            summary += f" (DNS query: {dns_queries[0]})"
        elif http_host:
            summary += f" (HTTP Host: {http_host.strip()})"
        elif tls_sni:
            summary += f" (TLS SNI: {tls_sni.strip().lower()})"

        packets.append({
            "index": pkt_idx,
            "timestamp": ts_val,
            "length": pkt_len,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto_clean,
            "dns_queries": dns_queries,
            "http_host": http_host.strip() or None,
            "tls_sni": tls_sni.strip().lower() or None,
            "summary": summary,
        })
    return packets


def _load_capture_packets(abs_path: str) -> Tuple[str, List[Dict[str, Any]]]:
    """
    Loads and dissects packets using tshark (if available on PATH), dpkt (if installed),
    or the built-in pure-Python pcap/pcapng parser.
    """
    forced_backend = os.environ.get("PCAP_PARSER_BACKEND", "").strip().lower()
    disable_builtin = os.environ.get("PCAP_DISABLE_BUILTIN_PARSER", "").strip() == "1"

    tshark_bin = None if forced_backend in ("python", "builtin", "dpkt", "none") else shutil.which("tshark")
    if tshark_bin and forced_backend != "none":
        try:
            return "tshark", _parse_with_tshark(tshark_bin, abs_path)
        except Exception as e:
            log_debug(f"tshark parsing failed ({e}); checking Python parser fallback.")

    if forced_backend == "none":
        raise RuntimeError(
            "No packet capture parser backend is available. Install 'tshark' (Wireshark CLI) on PATH "
            "or a supported Python packet parsing library (e.g. 'dpkt' or 'scapy')."
        )

    if not disable_builtin:
        return "python_builtin", _parse_pcap_builtin(abs_path)

    if HAS_DPKT and dpkt is not None:
        # Minimal dpkt fallback if builtin was disabled
        packets: List[Dict[str, Any]] = []
        with open(abs_path, "rb") as f:
            ext = os.path.splitext(abs_path)[1].lower()
            reader = dpkt.pcapng.Reader(f) if ext == ".pcapng" else dpkt.pcap.Reader(f)
            link_type = reader.datalink() if hasattr(reader, "datalink") else 1
            for idx, (ts, buf) in enumerate(reader, start=1):
                decoded = _decode_l2_l3_l4(buf, link_type)
                decoded["index"] = idx
                decoded["timestamp"] = float(ts)
                decoded["length"] = len(buf)
                packets.append(decoded)
        return "dpkt", packets

    raise RuntimeError(
        "No supported packet capture parser is available (tshark is not on PATH and no Python parser library is enabled). "
        "Install Wireshark/tshark or 'dpkt'/'scapy' to inspect capture files."
    )


def _format_utc(ts: Optional[float]) -> Optional[str]:
    if ts is None:
        return None
    return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).isoformat()


# ============================================================================
# Tool Implementations (Passive & Read-Only)
# ============================================================================

def summarize_pcap(file_path: str) -> Dict[str, Any]:
    """Summarizes a local .pcap or .pcapng file (size, packet count, time span, protocols, top IPs)."""
    abs_path, err = _validate_pcap_path(file_path)
    if err or not abs_path:
        return err or {"error": "Validation failed."}

    file_size = os.path.getsize(abs_path)
    try:
        backend, packets = _load_capture_packets(abs_path)
    except Exception as e:
        return {
            "file_path": abs_path,
            "file_size_bytes": file_size,
            "error": str(e),
        }

    proto_counts: Counter = Counter()
    src_ip_counts: Counter = Counter()
    dst_ip_counts: Counter = Counter()
    timestamps: List[float] = []

    for pkt in packets:
        proto = pkt.get("protocol") or "UNKNOWN"
        proto_counts[proto] += 1
        if pkt.get("src_ip"):
            src_ip_counts[pkt["src_ip"]] += 1
        if pkt.get("dst_ip"):
            dst_ip_counts[pkt["dst_ip"]] += 1
        if pkt.get("timestamp") is not None:
            timestamps.append(float(pkt["timestamp"]))

    time_span: Optional[Dict[str, Any]] = None
    if timestamps:
        t_min = min(timestamps)
        t_max = max(timestamps)
        time_span = {
            "start_utc": _format_utc(t_min),
            "end_utc": _format_utc(t_max),
            "duration_seconds": round(max(0.0, t_max - t_min), 6),
        }

    return {
        "file_path": abs_path,
        "file_size_bytes": file_size,
        "parser_backend": backend,
        "total_packets": len(packets),
        "time_span": time_span,
        "protocol_counts": dict(proto_counts.most_common(MAX_PROTOCOL_BUCKETS)),
        "top_source_ips": [
            {"ip": ip, "packet_count": cnt}
            for ip, cnt in src_ip_counts.most_common(MAX_TOP_IPS)
        ],
        "top_destination_ips": [
            {"ip": ip, "packet_count": cnt}
            for ip, cnt in dst_ip_counts.most_common(MAX_TOP_IPS)
        ],
    }


def extract_dns_and_http_hosts(file_path: str, limit: int = DEFAULT_HOST_LIMIT) -> Dict[str, Any]:
    """Extracts deduplicated DNS queried domains, HTTP Host headers, and TLS SNI hostnames."""
    abs_path, err = _validate_pcap_path(file_path)
    if err or not abs_path:
        return err or {"error": "Validation failed."}

    try:
        bounded_limit = max(1, min(int(limit), MAX_HOST_LIMIT))
    except (TypeError, ValueError):
        bounded_limit = DEFAULT_HOST_LIMIT

    try:
        backend, packets = _load_capture_packets(abs_path)
    except Exception as e:
        return {
            "file_path": abs_path,
            "error": str(e),
        }

    dns_seen: List[str] = []
    dns_set = set()
    http_seen: List[str] = []
    http_set = set()
    sni_seen: List[str] = []
    sni_set = set()

    for pkt in packets:
        for q in pkt.get("dns_queries") or []:
            if q and q not in dns_set:
                dns_set.add(q)
                dns_seen.append(q)
        http_host = pkt.get("http_host")
        if http_host and http_host not in http_set:
            http_set.add(http_host)
            http_seen.append(http_host)
        tls_sni = pkt.get("tls_sni")
        if tls_sni and tls_sni not in sni_set:
            sni_set.add(tls_sni)
            sni_seen.append(tls_sni)

    return {
        "file_path": abs_path,
        "parser_backend": backend,
        "limit": bounded_limit,
        "dns_queries": dns_seen[:bounded_limit],
        "dns_queries_total_unique": len(dns_seen),
        "http_hosts": http_seen[:bounded_limit],
        "http_hosts_total_unique": len(http_seen),
        "tls_sni_hosts": sni_seen[:bounded_limit],
        "tls_sni_hosts_total_unique": len(sni_seen),
        "truncated": (
            len(dns_seen) > bounded_limit
            or len(http_seen) > bounded_limit
            or len(sni_seen) > bounded_limit
        ),
    }


def _ip_matches_filter(pkt: Dict[str, Any], ip_filter_norm: str, cidr_net: Optional[Any]) -> bool:
    src_ip = pkt.get("src_ip")
    dst_ip = pkt.get("dst_ip")
    if cidr_net is not None:
        for candidate in (src_ip, dst_ip):
            if candidate:
                try:
                    if ipaddress.ip_address(candidate) in cidr_net:
                        return True
                except ValueError:
                    continue
        return False
    return src_ip == ip_filter_norm or dst_ip == ip_filter_norm


def filter_pcap_packets(
    file_path: str,
    protocol: Optional[str] = None,
    ip_filter: Optional[str] = None,
    limit: int = DEFAULT_PACKET_LIMIT,
) -> Dict[str, Any]:
    """Filters packets by protocol and/or IP (or CIDR) and returns bounded packet summaries."""
    abs_path, err = _validate_pcap_path(file_path)
    if err or not abs_path:
        return err or {"error": "Validation failed."}

    try:
        bounded_limit = max(1, min(int(limit), MAX_PACKET_LIMIT))
    except (TypeError, ValueError):
        bounded_limit = DEFAULT_PACKET_LIMIT

    proto_norm = protocol.strip().upper() if isinstance(protocol, str) and protocol.strip() else None
    ip_norm = ip_filter.strip() if isinstance(ip_filter, str) and ip_filter.strip() else None
    cidr_net = None
    if ip_norm and "/" in ip_norm:
        try:
            cidr_net = ipaddress.ip_network(ip_norm, strict=False)
        except ValueError:
            return {
                "file_path": abs_path,
                "error": f"Invalid IP/CIDR filter: '{ip_filter}'.",
            }
    elif ip_norm:
        try:
            ipaddress.ip_address(ip_norm)
        except ValueError:
            return {
                "file_path": abs_path,
                "error": f"Invalid IP address filter: '{ip_filter}'.",
            }

    try:
        backend, packets = _load_capture_packets(abs_path)
    except Exception as e:
        return {
            "file_path": abs_path,
            "error": str(e),
        }

    total_matches = 0
    matched_records: List[Dict[str, Any]] = []

    for pkt in packets:
        if proto_norm:
            pkt_proto = (pkt.get("protocol") or "").upper()
            # Allow filtering by TCP/UDP even when L7 protocol was classified as DNS/HTTP/TLS
            port_based_tcp = proto_norm == "TCP" and pkt_proto in ("TCP", "HTTP", "TLS")
            port_based_udp = proto_norm == "UDP" and pkt_proto in ("UDP", "DNS", "MDNS")
            if pkt_proto != proto_norm and not port_based_tcp and not port_based_udp:
                continue

        if ip_norm and not _ip_matches_filter(pkt, ip_norm, cidr_net):
            continue

        total_matches += 1
        if len(matched_records) < bounded_limit:
            src_disp = (
                f"{pkt['src_ip']}:{pkt['src_port']}"
                if pkt.get("src_ip") and pkt.get("src_port") is not None
                else pkt.get("src_ip")
            )
            dst_disp = (
                f"{pkt['dst_ip']}:{pkt['dst_port']}"
                if pkt.get("dst_ip") and pkt.get("dst_port") is not None
                else pkt.get("dst_ip")
            )
            matched_records.append({
                "index": pkt.get("index"),
                "timestamp_utc": _format_utc(pkt.get("timestamp")),
                "src": src_disp,
                "dst": dst_disp,
                "protocol": pkt.get("protocol"),
                "length": pkt.get("length"),
                "summary": pkt.get("summary"),
            })

    return {
        "file_path": abs_path,
        "parser_backend": backend,
        "filters": {
            "protocol": proto_norm,
            "ip_filter": ip_norm,
            "limit": bounded_limit,
        },
        "total_matches": total_matches,
        "returned_count": len(matched_records),
        "truncated": total_matches > len(matched_records),
        "packets": matched_records,
    }


# ============================================================================
# MCP Tool Registry Definitions
# ============================================================================

def get_tools_definition() -> List[Dict[str, Any]]:
    """Returns the MCP tool definitions for tools/list."""
    return [
        {
            "name": "summarize_pcap",
            "description": "Safely inspects a local .pcap or .pcapng file and returns file size, packet count, time span, protocol distribution, and top 10 source/destination IPs.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the local .pcap or .pcapng file.",
                    }
                },
                "required": ["file_path"],
            },
        },
        {
            "name": "extract_dns_and_http_hosts",
            "description": "Extracts deduplicated queried DNS domain names, HTTP Host headers, and TLS SNI hostnames from a local .pcap or .pcapng file.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the local .pcap or .pcapng file.",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum unique items to return per category (default: 50, max: 200).",
                        "default": 50,
                    },
                },
                "required": ["file_path"],
            },
        },
        {
            "name": "filter_pcap_packets",
            "description": "Filters packets in a local .pcap or .pcapng file by protocol and/or IP/CIDR and returns bounded packet summary records plus total match count.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the local .pcap or .pcapng file.",
                    },
                    "protocol": {
                        "type": "string",
                        "description": "Optional protocol name filter (e.g. 'DNS', 'HTTP', 'TLS', 'TCP', 'UDP', 'ICMP').",
                    },
                    "ip_filter": {
                        "type": "string",
                        "description": "Optional source or destination IP address or CIDR filter (e.g. '192.168.1.10' or '10.0.0.0/8').",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum packet summary records to return (default: 25, max: 100).",
                        "default": 25,
                    },
                },
                "required": ["file_path"],
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
            if tool_name == "summarize_pcap":
                res_data = summarize_pcap(file_path=args.get("file_path"))
            elif tool_name == "extract_dns_and_http_hosts":
                res_data = extract_dns_and_http_hosts(
                    file_path=args.get("file_path"),
                    limit=args.get("limit", DEFAULT_HOST_LIMIT),
                )
            elif tool_name == "filter_pcap_packets":
                res_data = filter_pcap_packets(
                    file_path=args.get("file_path"),
                    protocol=args.get("protocol"),
                    ip_filter=args.get("ip_filter"),
                    limit=args.get("limit", DEFAULT_PACKET_LIMIT),
                )
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
    parser = argparse.ArgumentParser(description="Local Packet Capture Inspector MCP Server")
    parser.parse_args()
    run_stdio_server()
