#!/usr/bin/env -S uv run --script
# /// script
# dependencies = ["dnspython"]
# ///
"""
Scan a large domain list against ACT's DNS interception proxy.

Methodology:
  Queries are sent ONLY to a non-routable RFC 5737 address (198.51.100.1).
  This IP cannot host a DNS server on the public internet. Any response
  received from it was forged by the ISP's inline interceptor.

  - Response with A record → domain is on the DNS blocklist
  - Timeout               → domain is NOT blocked (or genuinely unreachable)

This separates DNS-level blocking from HTTP-level blocking, which
script 03 handles separately.
"""

import dns.resolver
import dns.exception
import json
import os
import time
from datetime import datetime, timezone

DEAD_END = "198.51.100.1"
TIMEOUT = 2.0

# Comprehensive domain list across categories
DOMAINS = {
    "youtube": [
        "youtube.com", "www.youtube.com", "m.youtube.com",
        "music.youtube.com", "tv.youtube.com", "gaming.youtube.com",
        "studio.youtube.com", "news.youtube.com", "artists.youtube.com",
        "shorts.youtube.com", "education.youtube.com", "kids.youtube.com",
        "creator.youtube.com", "www.music.youtube.com",
    ],
    "google_properties": [
        "google.com", "www.google.com", "mail.google.com",
        "drive.google.com", "accounts.google.com", "docs.google.com",
        "maps.google.com", "photos.google.com", "play.google.com",
        "translate.google.com", "news.google.com",
    ],
    "piracy_torrent": [
        "thepiratebay.org", "1337x.to", "1337x.st", "x1337x.ws",
        "yts.mx", "yts.lt", "yts.am",
        "rarbg.to", "rarbg.com", "rarbgproxy.org",
        "torrentz2.eu", "limetorrents.info", "extratorrent.to",
        "extratorrent.ee", "nyaa.si", "nyaa.tracker.ee",
        "kickasstorrents.to", "kickass.to", "kat.cr",
        "torrentgalaxy.to", "torrentproject.pro", "magnetdl.com",
        "isohunt.to", "torrentdownloads.me", "yourbittorrent.com",
        "eztv.io", "eztv.ag", "limetorrents.cc",
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
        "threads.net", "mastodon.social",
    ],
    "messaging_voip": [
        "whatsapp.com", "telegram.org", "signal.org",
        "discord.com", "skype.com", "viber.com",
        "line.me", "kik.com", "imo.im", "wechat.com",
    ],
    "streaming_media": [
        "netflix.com", "primevideo.com", "hotstar.com",
        "sonyliv.com", "voot.com", "zee5.com",
        "mxplayer.in", "jiocinema.com", "aha.video",
        "twitch.tv", "dailymotion.com", "vimeo.com",
        "spotify.com", "soundcloud.com",
        "disneyplus.com", "hbo.com", "hulu.com",
    ],
    "news_media": [
        "bbc.com", "cnn.com", "reuters.com", "aljazeera.com",
        "ndtv.com", "thehindu.com", "timesofindia.com",
        "indianexpress.com", "hindustantimes.com",
        "wikipedia.org", "wikimedia.org",
        "archive.org", "archive.today",
        "reddit.com", "medium.com",
    ],
    "dev_tools": [
        "github.com", "gitlab.com", "bitbucket.org",
        "stackoverflow.com", "stackexchange.com",
        "npmjs.com", "pypi.org", "crates.io",
        "docker.com", "docker.io", "registry.k8s.io",
        "raw.githubusercontent.com", "gist.github.com",
    ],
    "vpn_proxy": [
        "protonvpn.com", "nordvpn.com", "expressvpn.com",
        "surfshark.com", "cyberghost.com", "tunnelbear.com",
        "mullvad.net", "privateinternetaccess.com",
        "windscribe.com", "vpnbook.com", "hide.me",
        "psiphon.ca", "softether.org", "openvpn.net",
        "torproject.org", "tails.net",
    ],
    "controls_neutral": [
        "example.com", "example.org", "example.net",
        "test.com", "iana.org", "rfc-editor.org",
        "ietf.org", "w3.org", "kernel.org",
        "google.com", "cloudflare.com", "amazonaws.com",
        "microsoft.com", "apple.com",
    ],
    "controls_nonexistent": [
        "this-does-not-exist-98765.com",
        "zzz-fake-domain-test-12345.org",
        "not-a-real-website-67890.net",
    ],
}


def query_dead_end(domain: str) -> dict:
    """Query the dead-end IP. Any response = interception."""
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [DEAD_END]
    resolver.lifetime = TIMEOUT
    resolver.timeout = TIMEOUT
    result = {
        "domain": domain,
        "queried_ip": DEAD_END,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    try:
        answers = resolver.resolve(domain, "A")
        ips = [str(r) for r in answers]
        result["blocked"] = True
        result["resolved_ips"] = ips
        result["sinkhole_ip"] = ips[0] if ips else None
    except dns.resolver.NXDOMAIN:
        result["blocked"] = False
        result["status"] = "NXDOMAIN"
    except dns.resolver.NoAnswer:
        result["blocked"] = False
        result["status"] = "NOANSWER"
    except dns.resolver.NoNameservers:
        result["blocked"] = False
        result["status"] = "NO_NAMESERVERS"
    except dns.exception.Timeout:
        result["blocked"] = False
        result["status"] = "TIMEOUT"
    except Exception as e:
        result["blocked"] = False
        result["status"] = f"ERROR: {e}"
    return result


def main():
    out_dir = os.path.join(os.path.dirname(__file__), "..", "evidence")
    os.makedirs(out_dir, exist_ok=True)

    all_results = {}
    blocked_count = 0
    total_count = 0

    print("=" * 72)
    print("  DNS BLOCKLIST SCAN (via dead-end 198.51.100.1)")
    print(f"  Timestamp: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 72)

    for category, domains in DOMAINS.items():
        print(f"\n  [{category}]")
        cat_results = []
        for domain in domains:
            r = query_dead_end(domain)
            r["category"] = category
            cat_results.append(r)
            total_count += 1
            if r["blocked"]:
                blocked_count += 1
                print(f"    ✗ BLOCKED   {domain:35s} → {r['sinkhole_ip']}")
            else:
                print(f"    ✓ passthru  {domain:35s} → {r.get('status', 'ok')}")
            time.sleep(0.1)  # gentle rate limit
        all_results[category] = cat_results

    out_path = os.path.join(out_dir, "02_blocklist_scan.json")
    with open(out_path, "w") as f:
        json.dump(all_results, f, indent=2)

    print(f"\n{'=' * 72}")
    print(f"  SUMMARY: {blocked_count} / {total_count} domains DNS-blocked")
    print(f"  Evidence written to: {out_path}")
    print(f"{'=' * 72}")

    # List all blocked domains
    print(f"\n  ALL DNS-BLOCKED DOMAINS:")
    for cat, results in all_results.items():
        for r in results:
            if r["blocked"]:
                print(f"    [{cat:20s}] {r['domain']:35s} → {r['sinkhole_ip']}")


if __name__ == "__main__":
    main()
