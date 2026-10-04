"""BlackEcho binary evidence generators (stdlib only, deterministic).

build_jpeg_with_exif: minimal JPEG with an EXIF APP1 segment carrying
    controlled metadata (Make/Model/DateTime/Software + GPS).
build_pcap: minimal PCAP with synthetic DNS query packets for the
    incident domain and benign distractors.
"""

from __future__ import annotations

import random
import struct


# ---------------------------------------------------------------------------
# JPEG + EXIF
# ---------------------------------------------------------------------------

def _tiff_entry(tag: int, typ: int, count: int, value: bytes) -> bytes:
    """One 12-byte IFD entry. value is packed inline if <=4 bytes."""
    if len(value) <= 4:
        value = value + b"\x00" * (4 - len(value))
        return struct.pack("<HHI4s", tag, typ, count, value)
    raise ValueError("only inline values supported")


def build_jpeg_with_exif(rng: random.Random) -> bytes:
    """Minimal JPEG with EXIF APP1: Make/Model/DateTime/Software/Copyright."""
    make = b"NorthstarCam\x00"
    model = b"NM-ScanPro 4000\x00"
    dt = b"2026:09:28 08:10:22\x00"  # 2 min before the email: plausible scan time
    software = b"NM Invoice Scanner 3.1\x00"
    # String table placed after the IFD
    strings = [
        (0x010F, make),      # Make
        (0x0110, model),     # Model
        (0x0132, dt),        # DateTime
        (0x0131, software),  # Software
        (0x8298, b"Northstar Meridian - synthetic evidence\x00"),  # Copyright
    ]
    n = len(strings)
    # TIFF header: II*\0 + offset to IFD0 (=8)
    tiff = b"II*\x00" + struct.pack("<I", 8)
    # IFD0: count (2 bytes) + n*12 bytes + next-IFD offset (4 bytes)
    ifd_offset = 8
    strings_base = ifd_offset + 2 + n * 12 + 4
    ifd = struct.pack("<H", n)
    blob = b""
    off = strings_base
    for tag, s in strings:
        ifd += struct.pack("<HHII", tag, 2, len(s), off)
        blob += s
        off += len(s)
    ifd += struct.pack("<I", 0)  # no next IFD
    tiff += ifd + blob

    exif_payload = b"Exif\x00\x00" + tiff
    app1 = b"\xff\xe1" + struct.pack(">H", len(exif_payload) + 2) + exif_payload

    # Minimal valid JPEG body: SOI + APP1 + DQT + SOF0 + DHT + SOS + EOI
    # (1x1 pixel, grayscale). MetaTrace only walks segments before SOS.
    jpeg = b"\xff\xd8" + app1
    # DQT (minimal)
    jpeg += b"\xff\xdb\x00\x43\x00" + bytes([8] * 64)
    # SOF0: 1x1, 1 component
    jpeg += b"\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00"
    # DHT (minimal DC table)
    jpeg += b"\xff\xc4\x00\x1f\x00" + bytes(28)
    # SOS
    jpeg += b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00"
    # Minimal entropy-coded data + EOI
    jpeg += b"\x00\xff\xd9"
    return jpeg


# ---------------------------------------------------------------------------
# PCAP with DNS queries
# ---------------------------------------------------------------------------

def _dns_query_packet(query: str, qtype: int = 1) -> bytes:
    """Ethernet + IPv4 + UDP + DNS query packet."""
    # DNS
    txid = 0xBEAC
    flags = 0x0100  # standard query
    qdcount, ancount, nscount, arcount = 1, 0, 0, 0
    dns = struct.pack(">HHHHHH", txid, flags, qdcount, ancount, nscount, arcount)
    for label in query.split("."):
        dns += struct.pack("B", len(label)) + label.encode()
    dns += b"\x00" + struct.pack(">HH", qtype, 1)  # QTYPE, QCLASS IN

    # UDP
    udp_len = 8 + len(dns)
    udp = struct.pack(">HHHH", 5353, 53, udp_len, 0) + dns  # checksum 0

    # IPv4 (10.20.30.44 -> 10.20.30.10)
    ip_len = 20 + udp_len
    ip = struct.pack(">BBHHHBBHII",
                     0x45, 0, ip_len, 0x1234, 0x4000, 64, 17, 0,
                     0x0A141E2C, 0x0A141E0A)  # 10.20.30.44 -> 10.20.30.10

    # Ethernet (dummy MACs)
    eth = b"\x00" * 12 + b"\x08\x00"
    return eth + ip + udp


def build_pcap() -> bytes:
    """PCAP global header + DNS query packets (incident + benign)."""
    # Global header: magic, v2.4, thiszone, sigfigs, snaplen, network=Ethernet
    pcap = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    queries = [
        ("invoice-portal-updates.example", 1),
        ("invoice-portal-updates.example", 28),
        ("intranet.northstar-meridian.example", 1),
        ("update.microsoft.com", 1),
    ]
    ts_sec = 1759047180  # 2026-09-28T08:13:00Z
    for i, (q, qt) in enumerate(queries):
        pkt = _dns_query_packet(q, qt)
        # Packet header: ts_sec, ts_usec, incl_len, orig_len
        pcap += struct.pack("<IIII", ts_sec + i * 5, 0, len(pkt), len(pkt)) + pkt
    return pcap
