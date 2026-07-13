#!/usr/bin/env -S uv run --script
# /// script
# dependencies = ["dnspython"]
# ///
"""
DNS blocklist matching-rule analysis.

Tests the interceptor's domain-matching logic to determine:
  - Exact match vs suffix/wildcard matching
  - Case sensitivity
  - Trailing dot handling
  - Subdomain inheritance (does blocking youtube.com block *.youtube.com?)
  - CNAME chain behavior
  - Wildcard/prepend injection (e.g. random.youtube.com)

This reveals whether ACT uses exact-match or regex/suffix blocklists.
"""

import dns.resolver
import dns.exception
import json
import os
import time
from datetime import datetime, timezone

DEAD_END = "198.51.100.1"
TIMEOUT = 3.0

SINKHOLE_PREFIX = "49.205."

# Known blocked base domains
BLOCKED_BASE = "youtube.com"
BLOCKED_SUB = "music.youtube.com"
NOT_BLOCKED_SUB = "www.youtube.com"


def query(domain: str) -> dict:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [DEAD_END]
    resolver.lifetime = TIMEOUT
    resolver.timeout = TIMEOUT
    result = {"domain": domain, "timestamp": datetime.now(timezone.utc).isoformat()}
    try:
        answers = resolver.resolve(domain, "A")
        ips = [str(r) for r in answers]
        result["ips"] = ips
        result["intercepted"] = any(ip.startswith(SINKHOLE_PREFIX) for ip in ips)
    except dns.resolver.NXDOMAIN:
        result["ips"] = []
        result["intercepted"] = False
        result["status"] = "NXDOMAIN"
    except dns.exception.Timeout:
        result["ips"] = []
        result["intercepted"] = False
        result["status"] = "TIMEOUT"
    except dns.resolver.NoNameservers:
        result["ips"] = []
        result["intercepted"] = False
        result["status"] = "NO_NAMESERVERS"
    except Exception as e:
        result["ips"] = []
        result["intercepted"] = False
        result["status"] = str(e)
    return result


def main():
    out_dir = os.path.join(os.path.dirname(__file__), "..", "evidence")
    os.makedirs(out_dir, exist_ok=True)

    all_results = []

    print("=" * 72)
    print("  DNS BLOCKLIST MATCHING-RULE ANALYSIS")
    print(f"  Timestamp: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 72)

    tests = {
        "exact_match": [
            ("youtube.com", "base domain"),
            ("music.youtube.com", "known blocked subdomain"),
            ("www.youtube.com", "known NOT blocked subdomain"),
            ("m.youtube.com", "known NOT blocked subdomain"),
        ],
        "case_insensitivity": [
            ("YOUTUBE.COM", "uppercase"),
            ("Youtube.Com", "mixed case"),
            ("music.YouTube.com", "mixed case subdomain"),
        ],
        "trailing_dot": [
            ("youtube.com.", "with trailing dot"),
            ("music.youtube.com.", "subdomain with trailing dot"),
        ],
        "subdomain_inheritance": [
            ("random123.youtube.com", "random subdomain of blocked base"),
            ("deep.sub.youtube.com", "deep subdomain"),
            ("random123.www.youtube.com", "random subdomain of NOT-blocked www"),
            ("x.music.youtube.com", "prepend to blocked subdomain"),
        ],
        "suffix_matching": [
            ("notyoutube.com", "contains 'youtube.com' as substring"),
            ("youtube.com.evil.com", "youtube.com as prefix of other domain"),
            ("evil.youtube.com.evil.com", "youtube.com in middle"),
        ],
        "different_blocked_bases": [
            ("tiktok.com", "base blocked"),
            ("www.tiktok.com", "www subdomain"),
            ("random.tiktok.com", "random subdomain"),
            ("thepiratebay.org", "base blocked"),
            ("x.thepiratebay.org", "subdomain"),
        ],
        "controls": [
            ("example.com", "control"),
            ("google.com", "control"),
            ("random123.example.com", "random subdomain of control"),
        ],
    }

    for category, domain_list in tests.items():
        print(f"\n  [{category}]")
        print(f"  {'─' * 68}")
        for domain, note in domain_list:
            r = query(domain)
            r["category"] = category
            r["note"] = note
            all_results.append(r)
            if r["intercepted"]:
                print(f"    ✗ INTERCEPTED  {domain:40s}  →  {r['ips']}  ({note})")
            else:
                print(f"    ✓ passthru    {domain:40s}  →  {r.get('status', r.get('ips'))}  ({note})")
            time.sleep(0.15)

    out_path = os.path.join(out_dir, "06_matching_rules.json")
    with open(out_path, "w") as f:
        json.dump(all_results, f, indent=2)

    # Analysis summary
    print(f"\n{'=' * 72}")
    print(f"  MATCHING-RULE ANALYSIS SUMMARY")
    print(f"{'=' * 72}")

    intercepted = [(r["domain"], r["note"]) for r in all_results if r["intercepted"]]
    passed = [(r["domain"], r.get("status", "ok")) for r in all_results if not r["intercepted"]]

    print(f"\n  Intercepted ({len(intercepted)}):")
    for d, note in intercepted:
        print(f"    ✗ {d:40s}  ({note})")
    print(f"\n  Passed through ({len(passed)}):")
    for d, status in passed:
        print(f"    ✓ {d:40s}  ({status})")

    # Deduce rules
    print(f"\n  DEDUCED RULES:")
    # Check if www.youtube.com is blocked
    www_blocked = any(r["domain"] == "www.youtube.com" and r["intercepted"] for r in all_results)
    random_yt_blocked = any(r["domain"] == "random123.youtube.com" and r["intercepted"] for r in all_results)
    print(f"    - www.youtube.com blocked: {'YES' if www_blocked else 'NO'}")
    print(f"    - random123.youtube.com blocked: {'YES' if random_yt_blocked else 'NO'}")
    if random_yt_blocked and not www_blocked:
        print(f"    → Wildcard *.youtube.com IS blocked, but www.youtube.com is EXEMPT (whitelisted)")
    elif not random_yt_blocked:
        print(f"    → Subdomains of youtube.com are NOT blanket-blocked (exact-match list)")

    print(f"\n  Evidence written to: {out_path}")


if __name__ == "__main__":
    main()
