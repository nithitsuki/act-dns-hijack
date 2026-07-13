#!/usr/bin/env -S uv run --script
# /// script
# dependencies = ["requests"]
# ///
"""
Probe the HTTP blockpage server and categorize legal-authority messages.

The DNS sinkhole IP (49.205.75.11) also runs an HTTP server that serves
block notices. Different Host headers produce different legal messages,
revealing the distinct legal authorities cited for each block.

This script:
  1. Sends HTTP/1.1 requests to the sinkhole IP with various Host headers
  2. Captures full response headers (including ACT infrastructure leaks)
  3. Categorizes the body text by legal authority
  4. Discovers that the HTTP blocklist is LARGER than the DNS blocklist
  5. Reveals the sinkhole is also a transparent HTTP proxy (non-blocked
     hosts get forwarded to real servers)
"""

import requests
import json
import os
import time
from datetime import datetime, timezone
from collections import defaultdict

SINKHOLE_IP = "49.205.75.11"
SINKHOLE_URL = f"http://{SINKHOLE_IP}/"

# Known legal message categories (discovered empirically)
LEGAL_CATEGORIES = {
    "Court Order": "This URL has been blocked under the instructions in compliance with the orders of a Hon'ble Court",
    "Govt Authority + Court": "The URL has been blocked as per the instructions of the Competent Government Authority/ in compliance to the orders of Court of Law",
    "Law Enforcement (LEA)": "The website has been blocked as per notice/direction of Law Enforcement Agencies(LEAs)",
    "MeitY / IT Act": "The website has been blocked as per order of the Ministry of Electronics and Information Technology under IT Act, 2000",
    "MeitY / IT Act (variant)": "This URL has been blocked as per the directions of the Ministry of Electronics and Information Technology",
    "Court Order (variant)": "This URL has been blocked as per the orders of the Hon'ble Court",
}

# Broader domain list than the DNS scan — HTTP blocklist may be larger
TEST_DOMAINS = {
    "youtube": [
        "youtube.com", "www.youtube.com", "m.youtube.com",
        "music.youtube.com", "tv.youtube.com", "gaming.youtube.com",
        "studio.youtube.com", "news.youtube.com", "artists.youtube.com",
        "shorts.youtube.com", "education.youtube.com", "kids.youtube.com",
    ],
    "piracy_torrent": [
        "thepiratebay.org", "1337x.to", "1337x.st", "x1337x.ws",
        "yts.mx", "yts.lt", "rarbg.to", "rarbg.com", "rarbgproxy.org",
        "torrentz2.eu", "limetorrents.info", "limetorrents.cc",
        "extratorrent.to", "extratorrent.ee", "nyaa.si",
        "kickasstorrents.to", "kickass.to", "kat.cr",
        "torrentgalaxy.to", "torrentproject.pro", "magnetdl.com",
        "isohunt.to", "torrentdownloads.me", "eztv.io", "eztv.ag",
        "yourbittorrent.com",
    ],
    "pornography": [
        "pornhub.com", "xvideos.com", "xhamster.com", "xnxx.com",
        "redtube.com", "youporn.com", "spankbang.com", "tube8.com",
        "brazzers.com", "playboy.com", "xhamster.desi",
    ],
    "social_media": [
        "facebook.com", "twitter.com", "x.com", "instagram.com",
        "tiktok.com", "www.tiktok.com", "douyin.com",
        "whatsapp.com", "telegram.org", "t.me",
        "signal.org", "discord.com", "reddit.com",
        "snapchat.com", "pinterest.com", "linkedin.com",
    ],
    "vpn_proxy": [
        "protonvpn.com", "nordvpn.com", "expressvpn.com",
        "surfshark.com", "mullvad.net", "torproject.org",
    ],
    "controls_neutral": [
        "example.com", "example.org", "iana.org",
        "github.com", "google.com", "wikipedia.org",
        "amazon.in", "flipkart.com", "irctc.co.in",
    ],
    "controls_nonexistent": [
        "this-does-not-exist-98765.com",
        "zzz-fake-domain-test-12345.org",
    ],
}


def categorize_message(body: str) -> str:
    """Return the legal authority category for a block message."""
    for category, pattern in LEGAL_CATEGORIES.items():
        if pattern.lower() in body.lower():
            return category
    return "UNCATEGORIZED"


def probe_host(host: str) -> dict:
    """Send HTTP request to sinkhole with a specific Host header."""
    result = {
        "host": host,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    try:
        resp = requests.get(
            SINKHOLE_URL,
            headers={"Host": host},
            timeout=5,
            allow_redirects=False,
        )
        result["status_code"] = resp.status_code
        result["reason"] = resp.reason
        result["response_headers"] = dict(resp.headers)
        body = resp.text.strip()
        result["body"] = body

        if resp.status_code == 404 and "blocked" in body.lower():
            result["blocked"] = True
            result["category"] = categorize_message(body)
            result["block_message"] = body
        else:
            result["blocked"] = False
            # Check if it's a transparent-proxy pass-through (real server response)
            if resp.status_code in (200, 301, 302, 520) and "blocked" not in body.lower():
                result["proxy_passthrough"] = True
                result["category"] = "TRANSPARENT_PROXY_PASSTHROUGH"
            elif "No site configured" in body:
                result["category"] = "NO_SITE_CONFIGURED"
            else:
                result["category"] = "OTHER"

    except requests.exceptions.Timeout:
        result["blocked"] = False
        result["category"] = "TIMEOUT"
    except Exception as e:
        result["blocked"] = False
        result["category"] = f"ERROR: {e}"
    return result


def main():
    out_dir = os.path.join(os.path.dirname(__file__), "..", "evidence")
    os.makedirs(out_dir, exist_ok=True)

    all_results = {}
    blocked_by_category = defaultdict(list)
    passthrough_domains = []

    print("=" * 72)
    print("  HTTP BLOCKPAGE PROBE & LEGAL-AUTHORITY CATEGORIZATION")
    print(f"  Sinkhole: {SINKHOLE_IP}")
    print(f"  Timestamp: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 72)

    # First: capture the infrastructure headers (no Host header / default)
    print("\n  --- INFRASTRUCTURE HEADER LEAK (default request) ---")
    infra = requests.get(SINKHOLE_URL, timeout=5, allow_redirects=False)
    print(f"  Status: {infra.status_code}")
    for k, v in infra.headers.items():
        if k.lower().startswith("x-bg-") or k.lower().startswith("x-ratelimit"):
            print(f"    {k}: {v}")

    # Now probe all domains
    for category, domains in TEST_DOMAINS.items():
        print(f"\n  [{category}]")
        cat_results = []
        for domain in domains:
            r = probe_host(domain)
            r["domain_category"] = category
            cat_results.append(r)

            if r.get("blocked"):
                blocked_by_category[r["category"]].append(domain)
                print(f"    ✗ BLOCKED  {domain:30s} [{r['category']}]")
            elif r.get("proxy_passthrough"):
                passthrough_domains.append(domain)
                print(f"    → PROXY    {domain:30s} HTTP {r['status_code']} (transparent proxy)")
            else:
                print(f"    ✓ other    {domain:30s} [{r['category']}]")
            time.sleep(0.1)
        all_results[category] = cat_results

    out_path = os.path.join(out_dir, "03_blockpage_messages.json")
    with open(out_path, "w") as f:
        json.dump(all_results, f, indent=2)

    print(f"\n{'=' * 72}")
    print(f"  LEGAL AUTHORITY CATEGORIES DISCOVERED:")
    print(f"{'=' * 72}")
    for cat, domains in sorted(blocked_by_category.items()):
        print(f"\n  {cat} ({len(domains)} domains):")
        for d in domains:
            print(f"    - {d}")

    print(f"\n{'=' * 72}")
    print(f"  TRANSPARENT PROXY PASS-THROUGH ({len(passthrough_domains)} domains):")
    print(f"  (Non-blocked Hosts forwarded to real servers)")
    print(f"{'=' * 72}")
    for d in passthrough_domains:
        print(f"    - {d}")

    print(f"\n  Evidence written to: {out_path}")


if __name__ == "__main__":
    main()
