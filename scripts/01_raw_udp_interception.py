#!/usr/bin/env -S uv run --script
# /// script
# dependencies = ["dnspython"]
# ///
"""
Prove DNS interception with raw UDP socket queries.

Sends hand-crafted DNS queries to multiple destinations simultaneously:
  - Real resolvers (1.1.1.1, 8.8.8.8, 9.9.9.9)
  - Non-routable RFC 5737 documentation IPs (198.51.100.1, 203.0.113.1)
  - A port that never runs DNS (e.g. 192.0.2.1:53)

If a response comes back from a non-routable IP, interception is proven:
the packet never reached the internet. An intermediate device answered.

Uses raw sockets (not dnspython's resolver) so we can set arbitrary
destination IPs and inspect every byte of the response, including
query-ID echo and flags.
"""

import socket
import struct
import time
import json
import sys
import os
from datetime import datetime, timezone

# DNS query builder for a single A-record question
def build_dns_query(domain: str, query_id: int = 0x1234, rd: bool = True) -> bytes:
    """Build a raw DNS query packet for an A record."""
    # Header: ID(2) | flags(2) | qdcount(2) | ancount(2) | nscount(2) | arcount(2)
    flags = 0x0100 if rd else 0x0000  # RD bit
    header = struct.pack("!HHHHHH", query_id, flags, 1, 0, 0, 0)
    # Question section
    qname = b"".join(
        bytes([len(label)]) + label.encode() for label in domain.rstrip(".").split(".")
    ) + b"\x00"
    qtype = 1   # A
    qclass = 1  # IN
    question = qname + struct.pack("!HH", qtype, qclass)
    return header + question


def parse_dns_flags(flags: int) -> dict:
    return {
        "qr":     bool(flags & 0x8000),
        "opcode": (flags >> 11) & 0xF,
        "aa":     bool(flags & 0x0400),
        "tc":     bool(flags & 0x0200),
        "rd":     bool(flags & 0x0100),
        "ra":     bool(flags & 0x0080),
        "z":      (flags >> 4) & 0x7,
        "rcode":  flags & 0xF,
    }


def parse_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    labels = []
    jumped = False
    original_offset = offset
    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if not jumped:
                original_offset = offset + 2
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            offset = pointer
            jumped = True
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
        offset += length
    name = ".".join(labels)
    return name, (original_offset if jumped else offset)


def parse_dns_response(data: bytes) -> dict:
    if len(data) < 12:
        return {"error": "packet too short", "raw_len": len(data)}
    qid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    offset = 12
    questions = []
    for _ in range(qd):
        name, offset = parse_dns_name(data, offset)
        qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
        offset += 4
        questions.append({"name": name, "type": qtype, "class": qclass})
    answers = []
    for _ in range(an):
        name, offset = parse_dns_name(data, offset)
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlength]
        offset += rdlength
        if rtype == 1 and rdlength == 4:  # A record
            rdata = ".".join(str(b) for b in rdata)
        elif rtype == 5:  # CNAME
            cname, _ = parse_dns_name(data, offset - rdlength)
            rdata = cname
        answers.append({
            "name": name, "type": rtype, "class": rclass,
            "ttl": ttl, "rdata": rdata,
        })
    return {
        "id": qid,
        "flags": parse_dns_flags(flags),
        "raw_flags": f"0x{flags:04x}",
        "qdcount": qd, "ancount": an, "nscount": ns, "arcount": ar,
        "questions": questions,
        "answers": answers,
        "raw_hex": data.hex(),
    }


def query_udp(dest_ip: str, domain: str, port: int = 53,
              timeout: float = 3.0, query_id: int = 0x1234) -> dict:
    """Send a raw UDP DNS query and return parsed result or timeout."""
    packet = build_dns_query(domain, query_id)
    result = {
        "destination": f"{dest_ip}:{port}",
        "domain": domain,
        "query_id_sent": query_id,
        "sent_packet_hex": packet.hex(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (dest_ip, port))
        start = time.time()
        data, addr = sock.recvfrom(4096)
        elapsed = (time.time() - start) * 1000
        result["response_received"] = True
        result["responder_ip"] = addr[0]
        result["responder_port"] = addr[1]
        result["elapsed_ms"] = round(elapsed, 2)
        result["response"] = parse_dns_response(data)
        result["query_id_matches"] = (parse_dns_response(data).get("id") == query_id)
    except socket.timeout:
        result["response_received"] = False
        result["error"] = "timeout"
    except OSError as e:
        result["response_received"] = False
        result["error"] = str(e)
    finally:
        sock.close()
    return result


# Test destinations: mix of real resolvers and impossible addresses
REAL_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
DEAD_ENDS = [
    "198.51.100.1",  # RFC 5737 TEST-NET-2
    "203.0.113.1",  # RFC 5737 TEST-NET-3
    "192.0.2.1",    # RFC 5737 TEST-NET-1
]

TEST_DOMAINS = [
    ("music.youtube.com", "blocked"),
    ("youtube.com", "blocked"),
    ("tiktok.com", "blocked"),
    ("thepiratebay.org", "blocked"),
    ("example.com", "not-blocked control"),
    ("github.com", "not-blocked control"),
    ("this-does-not-exist-98765.com", "nonexistent control"),
]


def main():
    out_dir = os.path.join(os.path.dirname(__file__), "..", "evidence")
    os.makedirs(out_dir, exist_ok=True)

    all_results = []
    print("=" * 72)
    print("  RAW UDP DNS INTERCEPTION TEST")
    print(f"  Timestamp: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 72)

    for domain, category in TEST_DOMAINS:
        print(f"\n{'─' * 72}")
        print(f"  Domain: {domain}  [{category}]")
        print(f"{'─' * 72}")
        for dest in REAL_RESOLVERS + DEAD_ENDS:
            qid = hash((dest, domain)) & 0xFFFF  # distinctive ID per pair
            r = query_udp(dest, domain, query_id=qid)
            r["category"] = category
            r["is_dead_end"] = dest in DEAD_ENDS
            all_results.append(r)

            if r["response_received"]:
                resp = r["response"]
                answers = ", ".join(
                    a["rdata"] for a in resp.get("answers", []) if isinstance(a["rdata"], str)
                ) or "(empty)"
                id_match = "✓" if r.get("query_id_matches") else "✗ MISMATCH"
                print(f"  {dest:>18}  →  {r['responder_ip']:>15}  "
                      f"aa={resp['flags']['aa']}  id:{id_match}  "
                      f"{r['elapsed_ms']:.1f}ms  answers: {answers}")
                if r["is_dead_end"]:
                    print(f"                       ⚠ RESPONSE FROM NON-ROUTABLE IP — INTERCEPTION PROVEN")
            else:
                tag = "timeout (no interception)" if r["is_dead_end"] else r.get("error", "")
                print(f"  {dest:>18}  →  {'—':>15}  {tag}")

    out_path = os.path.join(out_dir, "01_raw_udp_interception.json")
    with open(out_path, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\n  Evidence written to: {out_path}")

    # Summary verdict
    dead_end_responses = [r for r in all_results if r["is_dead_end"] and r["response_received"]]
    print(f"\n{'=' * 72}")
    print(f"  VERDICT: {len(dead_end_responses)} responses received from non-routable IPs")
    print(f"  (RFC 5737 addresses cannot host DNS servers on the public internet.)")
    print(f"  These responses were forged by an inline interception device.")
    print(f"{'=' * 72}")


if __name__ == "__main__":
    main()
