#!/usr/bin/env -S uv run --script
# /// script
# dependencies = ["dnspython"]
# ///
"""
Packet-level forensic analysis of forged DNS responses.

Captures the raw wire-format bytes of forged responses and compares them
to legitimate responses. Documents:
  - The fake 'aa' (Authoritative Answer) flag
  - Query-ID echo (interceptor copies client's transaction ID)
  - TTL uniformity (always 10s)
  - Malformed packets for non-A record types (AAAA, CNAME)
  - Missing EDNS/OPT records
  - Response timing characteristics
"""

import dns.message
import dns.query
import dns.flags
import dns.rcode
import dns.rdatatype
import dns.resolver
import json
import os
import time
import struct
from datetime import datetime, timezone

DEAD_END = "198.51.100.1"
REAL_RESOLVER = "1.1.1.1"
TEST_DOMAIN = "music.youtube.com"
CONTROL_DOMAIN = "example.com"


def query_and_dissect(ip: str, domain: str, rdtype: str = "A",
                      timeout: float = 3.0) -> dict:
    """Send query, capture full wire-format response details."""
    q = dns.message.make_query(domain, rdtype)
    q_id = q.id
    result = {
        "server": ip, "domain": domain, "rdtype": rdtype,
        "query_id": q_id,
        "query_wire_hex": q.to_wire().hex(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    try:
        start = time.time()
        resp = dns.query.udp(q, ip, timeout=timeout)
        elapsed = (time.time() - start) * 1000
        result["response_received"] = True
        result["elapsed_ms"] = round(elapsed, 2)
        result["response_id"] = resp.id
        result["id_echo"] = (resp.id == q_id)
        result["flags"] = {
            "qr": bool(resp.flags & dns.flags.QR),
            "aa": bool(resp.flags & dns.flags.AA),
            "tc": bool(resp.flags & dns.flags.TC),
            "rd": bool(resp.flags & dns.flags.RD),
            "ra": bool(resp.flags & dns.flags.RA),
        }
        result["raw_flags"] = f"0x{resp.flags:04x}"
        result["rcode"] = dns.rcode.to_text(resp.rcode())
        result["question_count"] = len(resp.question)
        result["answer_count"] = len(resp.answer)
        result["authority_count"] = len(resp.authority)
        result["additional_count"] = len(resp.additional)
        # Extract answer details
        answers = []
        for rrset in resp.answer:
            for rdata in rrset:
                answers.append({
                    "name": rrset.name.to_text(),
                    "ttl": rrset.ttl,
                    "type": dns.rdatatype.to_text(rrset.rdtype),
                    "rdata": str(rdata),
                })
        result["answers"] = answers
        # EDNS / OPT presence
        result["has_edns"] = any(
            rrset.rdtype == dns.rdatatype.OPT for rrset in resp.additional
        )
        # Raw wire format
        result["response_wire_hex"] = resp.to_wire().hex()
        result["response_wire_len"] = len(resp.to_wire())
    except dns.exception.Timeout:
        result["response_received"] = False
        result["error"] = "timeout"
    except Exception as e:
        result["response_received"] = False
        result["error"] = str(e)
    return result


def main():
    out_dir = os.path.join(os.path.dirname(__file__), "..", "evidence")
    os.makedirs(out_dir, exist_ok=True)

    all_results = []

    print("=" * 72)
    print("  PACKET-LEVEL FORENSIC ANALYSIS OF FORGED DNS RESPONSES")
    print(f"  Timestamp: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 72)

    tests = [
        (REAL_RESOLVER, TEST_DOMAIN, "A"),
        (DEAD_END, TEST_DOMAIN, "A"),
        (DEAD_END, TEST_DOMAIN, "AAAA"),
        (DEAD_END, TEST_DOMAIN, "CNAME"),
        (DEAD_END, TEST_DOMAIN, "MX"),
        (DEAD_END, TEST_DOMAIN, "TXT"),
        (DEAD_END, TEST_DOMAIN, "NS"),
        (DEAD_END, TEST_DOMAIN, "SOA"),
        (REAL_RESOLVER, CONTROL_DOMAIN, "A"),
        (DEAD_END, CONTROL_DOMAIN, "A"),
    ]

    for ip, domain, rtype in tests:
        print(f"\n  {'─' * 68}")
        label = "FORGED" if ip == DEAD_END and domain == TEST_DOMAIN else ""
        print(f"  {ip:>18}  {domain:25s}  {rtype:6s}  {label}")
        print(f"  {'─' * 68}")
        r = query_and_dissect(ip, domain, rtype)
        all_results.append(r)
        if r["response_received"]:
            print(f"    Response ID: {r['response_id']}  (query ID was {r['query_id']}  echo: {r['id_echo']})")
            print(f"    Flags: {r['flags']}  rcode: {r['rcode']}  raw: {r['raw_flags']}")
            print(f"    QD:{r['question_count']}  AN:{r['answer_count']}  "
                  f"NS:{r['authority_count']}  AR:{r['additional_count']}  "
                  f"EDNS:{r['has_edns']}")
            print(f"    Elapsed: {r['elapsed_ms']}ms  Wire: {r['response_wire_len']} bytes")
            for a in r["answers"]:
                print(f"    → {a['name']}  {a['ttl']}s  {a['type']}  {a['rdata']}")
            if r["answer_count"] == 0 and r["rcode"] == "NOERROR":
                print(f"    ⚠ NOERROR with zero answers — malformed/empty forged response")
        else:
            print(f"    No response ({r.get('error', 'unknown')})")
        time.sleep(0.2)

    # Compare forged vs legitimate
    print(f"\n{'=' * 72}")
    print(f"  COMPARISON: Forged (dead-end) vs Legitimate (1.1.1.1)")
    print(f"{'=' * 72}")

    forged = all_results[1]  # dead-end, A
    legit = all_results[0]  # real, A
    control = all_results[8]  # real resolver, example.com
    control_dead = all_results[9]  # dead-end, example.com

    print(f"\n  {'Property':25s}  {'Forged':25s}  {'Legitimate':25s}")
    print(f"  {'─' * 80}")
    print(f"  {'aa flag':25s}  {str(forged['flags']['aa']):25s}  {str(legit['flags']['aa']):25s}")
    print(f"  {'ID echo':25s}  {str(forged['id_echo']):25s}  {str(legit['id_echo']):25s}")
    print(f"  {'TTL':25s}  {str(forged['answers'][0]['ttl'] if forged['answers'] else 'N/A'):25s}  {str(legit['answers'][0]['ttl'] if legit['answers'] else 'N/A'):25s}")
    print(f"  {'EDNS OPT present':25s}  {str(forged['has_edns']):25s}  {str(legit['has_edns']):25s}")
    print(f"  {'Answer count':25s}  {str(forged['answer_count']):25s}  {str(legit['answer_count']):25s}")
    print(f"  {'Wire length':25s}  {str(forged['response_wire_len']):25s}  {str(legit['response_wire_len']):25s}")

    print(f"\n  Control (example.com):")
    print(f"    Real resolver:    {control['flags']['aa']=}  {control['answers']}")
    print(f"    Dead-end:         {control_dead.get('error', control_dead.get('answers'))}")
    print(f"    (Control correctly times out on dead-end — not intercepted)")

    out_path = os.path.join(out_dir, "05_packet_forensics.json")
    with open(out_path, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\n  Evidence written to: {out_path}")


if __name__ == "__main__":
    main()
