# ACT Fibernet Transparent DNS Proxy Investigation

Forensic investigation of **unauthorized DNS interception and packet forgery** deployed by Atria Convergence Technologies Ltd. (ACT Fibernet, AS24309) on its residential broadband network.

All evidence is **reproducible by any subscriber on the ACT network** using the scripts in this repository.

---

## Table of Contents

- [Executive Summary](#executive-summary)
- [How to Reproduce](#how-to-reproduce)
- [The Mechanism](#the-mechanism)
- [Evidence & Findings](#evidence--findings)
  - [1. Raw UDP Interception Proof](#1-raw-udp-interception-proof)
  - [2. Blocklist Scope](#2-blocklist-scope)
  - [3. Blockpage Legal Categories](#3-blockpage-legal-categories)
  - [4. Transport-Layer Bypass](#4-transport-layer-bypass)
  - [5. Packet-Level Forensics](#5-packet-level-forensics)
  - [6. Matching-Rule Analysis](#6-matching-rule-analysis)
- [Key Discoveries Beyond the Initial Report](#key-discoveries-beyond-the-initial-report)
- [Technical Violations](#technical-violations)
- [Repository Structure](#repository-structure)

---

## Executive Summary

ACT Fibernet operates an **inline transparent DNS proxy** that intercepts all outbound UDP port 53 traffic within its network. Instead of forwarding DNS queries to their intended destination, the proxy inspects the query payload and, if the queried domain matches an internal blocklist, injects a forged DNS response redirecting the user to an ACT-controlled sinkhole IP (`49.205.75.11`).

This is **not** standard DNS filtering (where a resolver you configure returns NXDOMAIN or a blockpage). This is **packet interception on the wire** — the proxy intercepts queries even when directed at third-party DNS servers (1.1.1.1, 8.8.8.8, 9.9.9.9) and even when directed at **non-routable IP addresses that cannot possibly host a DNS server**.

The sinkhole also runs an HTTP server that serves court-order block notices, categorized by four distinct legal authorities. It additionally functions as a **transparent HTTP proxy**, forwarding non-blocked Host headers to real upstream servers.

---

## How to Reproduce

### Prerequisites

- A machine connected to the ACT Fibernet network
- [`uv`](https://docs.astral.sh/uv/) installed (Python package runner)

### Run the Full Suite

```bash
git clone <this-repo>
cd act-transparent-proxy-bans
./run_all.sh
```

This runs all six scripts and writes JSON evidence to `./evidence/`.

### Run Individual Scripts

```bash
uv run scripts/01_raw_udp_interception.py   # Core proof: responses from non-routable IPs
uv run scripts/02_blocklist_scan.py          # Scan ~170 domains for DNS blocking
uv run scripts/03_blockpage_messages.py      # HTTP blockpage legal categories
uv run scripts/04_transport_bypass.py        # TCP/DoT/DoH bypass tests
uv run scripts/05_packet_forensics.py        # Wire-format packet analysis
uv run scripts/06_matching_rules.py          # Blocklist matching logic
```

Each script is self-contained with inline `uv` script dependencies — no manual environment setup required.

---

## The Mechanism

```
                         ACT NETWORK
  ┌─────────┐     UDP/53    ┌──────────────┐     UDP/53    ┌───────────┐
  │ Your    │ ────────────▶ │  Inline DNS  │ ────────────▶ │ 1.1.1.1   │
  │ Machine │               │  Interceptor │               │ 8.8.8.8   │
  │         │ ◀──────────── │  (forging   │ ◀──────────── │ 9.9.9.9   │
  │         │   forged resp  │   proxy)    │               │ etc.      │
  └─────────┘               └──────────────┘               └───────────┘
                                  │
                                  │ if domain matches blocklist:
                                  │ returns 49.205.75.11 immediately
                                  │ (query never reaches the internet)
                                  ▼
                           ┌──────────────┐
                           │  Sinkhole    │
                           │ 49.205.75.11 │
                           │ bgact-       │
                           │ bangalore1   │
                           │              │
                           │ HTTP 404     │
                           │ "Blocked"    │
                           └──────────────┘
```

### What Happens Step-by-Step

1. Your machine sends a UDP DNS query to *any* destination IP on port 53.
2. ACT's inline interceptor captures the packet **before it leaves the ACT network**.
3. The interceptor inspects the DNS query name in the payload.
4. **If the domain is on the blocklist**: the interceptor generates a forged DNS response with:
   - The `aa` (Authoritative Answer) flag set
   - An A record pointing to `49.205.75.11` (ACT's sinkhole)
   - TTL of 10 seconds
   - The same query ID as the client's original query
5. **If the domain is NOT on the blocklist**: the interceptor allows the packet to pass through to the real destination.
6. Your machine receives the forged response, believing it came from the resolver you specified.

### Proof It's Interception, Not Resolver-Side Blocking

The critical experiment: send DNS queries to **`198.51.100.1`**, an IP in RFC 5737 TEST-NET-2 — a range reserved for documentation that **cannot route on the public internet** and cannot host a DNS server.

If you get a response from this address, the packet never reached the internet. An in-network device answered it.

```
$ dig @198.51.100.1 music.youtube.com

;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 17597
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

music.youtube.com.    10    IN    A    49.205.75.11

;; SERVER: 198.51.100.1#53(198.51.100.1) (UDP)
```

A response from `198.51.100.1` is a **physical impossibility** without inline interception.

---

## Evidence & Findings

### 1. Raw UDP Interception Proof

**Script:** `scripts/01_raw_udp_interception.py`
**Evidence:** `evidence/01_raw_udp_interception.json`

Sends hand-crafted raw UDP DNS queries to six destinations simultaneously:
- **Real resolvers:** 1.1.1.1, 8.8.8.8, 9.9.9.9
- **Non-routable IPs:** 198.51.100.1, 203.0.113.1, 192.0.2.1 (RFC 5737)

| Domain | 1.1.1.1 (UDP) | 198.51.100.1 (UDP) | Verdict |
|---|---|---|---|
| music.youtube.com | `49.205.75.11` (aa=true) | `49.205.75.11` (aa=true) | **Intercepted** |
| youtube.com | `49.205.75.11` (aa=true) | `49.205.75.11` (aa=true) | **Intercepted** |
| tiktok.com | `49.205.75.11` (aa=true) | `49.205.75.11` (aa=true) | **Intercepted** |
| thepiratebay.org | `49.205.75.11` (aa=true) | `49.205.75.11` (aa=true) | **Intercepted** |
| example.com | `104.20.23.154` (aa=false) | timeout | Not intercepted |
| github.com | `20.207.73.82` (aa=false) | timeout | Not intercepted |
| nonexistent | (empty) | timeout | Not intercepted |

**Result:** 12 forged responses received from 3 non-routable IPs. Interception is definitively proven.

---

### 2. Blocklist Scope

**Script:** `scripts/02_blocklist_scan.py`
**Evidence:** `evidence/02_blocklist_scan.json`

Scans ~170 domains across 12 categories by querying the non-routable IP `198.51.100.1`. A response = intercepted; a timeout = not intercepted.

**49 domains DNS-blocked**, all resolving to `49.205.75.11`:

| Category | Blocked Domains |
|---|---|
| **YouTube** (12) | youtube.com, music., tv., gaming., studio., news., artists., shorts., education., kids., creator., www.music.youtube.com |
| **Piracy / Torrent** (24) | thepiratebay.org, 1337x.to, 1337x.st, x1337x.ws, yts.mx, yts.lt, yts.am, rarbg.to, rarbg.com, rarbgproxy.org, torrentz2.eu, limetorrents.info, limetorrents.cc, nyaa.si, kickasstorrents.to, kickass.to, kat.cr, torrentgalaxy.to, magnetdl.com, torrentdownloads.me, yourbittorrent.com, eztv.io, eztv.ag |
| **Pornography** (11) | pornhub.com, xvideos.com, xhamster.com, xnxx.com, redtube.com, youporn.com, tube8.com, brazzers.com, playboy.com, xhamster.desi |
| **Social Media** (2) | tiktok.com, www.tiktok.com |
| **Messaging** (1) | wechat.com |
| **Archives** (1) | archive.today |

**NOT blocked (controls):** google.com, facebook.com, twitter.com, x.com, whatsapp.com, telegram.org, reddit.com, wikipedia.org, github.com, netflix.com, all VPN sites, example.com, and all nonexistent test domains.

Key observation: the blocking is a **curated target list**, not blanket filtering.

---

### 3. Blockpage Legal Categories

**Script:** `scripts/03_blockpage_messages.py`
**Evidence:** `evidence/03_blockpage_messages.json`

The sinkhole `49.205.75.11` runs an HTTP server. Sending requests with different `Host` headers reveals that each blocked domain is associated with a specific legal authority. **Four distinct categories** were discovered:

#### Court Order
```
HTTP/1.1 404 Denied
Content-type: text/plain

This URL has been blocked under the instructions in compliance with the orders of a Hon'ble Court.
```
**18 domains:** all YouTube subdomains, yts.mx/lt, torrentgalaxy.to, magnetdl.com, pornhub.com, x1337x.ws

#### Government Authority + Court
```
HTTP/1.1 404 Denied
Content-type: text/plain

The URL has been blocked as per the instructions of the Competent Government Authority/ in compliance to the orders of Court of Law.
```
**11 domains:** 1337x.to/st, rarbg.to/com/proxy, torrentz2.eu, nyaa.si, kickasstorrents.to, kat.cr, tiktok.com, www.tiktok.com

#### Law Enforcement Agencies (LEAs)
```
HTTP/1.1 404 Denied
Content-type: text/plain

The website has been blocked as per notice/direction of Law Enforcement Agencies(LEAs).
```
**10 domains:** thepiratebay.org, kickass.to, xvideos.com, xhamster.com, xnxx.com, redtube.com, youporn.com, tube8.com, brazzers.com, playboy.com

#### MeitY / IT Act, 2000
```
HTTP/1.1 404 Denied
Content-type: text/plain

The website has been blocked as per order of the Ministry of Electronics and Information Technology under IT Act, 2000.
```
**7 domains:** limetorrents.info/cc, torrentdownloads.me, eztv.io/ag, yourbittorrent.com, xhamster.desi

#### Infrastructure Header Leak

The sinkhole leaks ACT backend infrastructure headers:
```
X-Bg-Hostname: bgact-bangalore1
X-Bg-Tenantid: 0
X-Bg-Tenantname: default
X-Bg-Using-Ip: <your-client-IP>
X-Ratelimit-Remaining: 99
```

#### Two-Tier Blocking Discovery

The HTTP blocklist is **larger** than the DNS blocklist. Domains like `www.youtube.com` and `m.youtube.com` are **NOT** DNS-blocked (their DNS queries pass through to real resolvers), but they **ARE** blocked at the HTTP layer (the sinkhole serves a court-order blockpage for these Host headers). This proves ACT operates two independent blocking systems.

#### Transparent HTTP Proxy

The sinkhole also functions as a **transparent HTTP proxy** for non-blocked Host headers. Requests with Host headers like `github.com`, `x.com`, `amazon.in` are forwarded to real upstream servers, and genuine responses are returned. This is incidental infrastructure leakage — the same server handles both blocking and proxying.

---

### 4. Transport-Layer Bypass

**Script:** `scripts/04_transport_bypass.py`
**Evidence:** `evidence/04_transport_bypass.json`

Tests whether switching transport protocols bypasses the interception.

| Transport | Server | music.youtube.com | Verdict |
|---|---|---|---|
| **UDP** port 53 | 1.1.1.1 | `49.205.75.11` (forged) | **Intercepted** |
| **UDP** port 53 | 198.51.100.1 | `49.205.75.11` (forged) | **Intercepted** |
| **TCP** port 53 | 1.1.1.1 | `142.251.x.x` (real Google IPs) | **Bypassed** |
| **TCP** port 53 | 198.51.100.1 | timeout (no interception) | **Bypassed** |
| **DoT** port 853 | 1.1.1.1 | `142.251.x.x` (real) | **Bypassed** |
| **DoH** port 443 | cloudflare | `142.251.x.x` (real) | **Bypassed** |

**Finding:** The interception is **UDP-only**. TCP DNS, DNS-over-TLS, and DNS-over-HTTPS all return legitimate answers. The interceptor only inspects UDP port 53.

---

### 5. Packet-Level Forensics

**Script:** `scripts/05_packet_forensics.py`
**Evidence:** `evidence/05_packet_forensics.json`

Dissects the raw wire-format bytes of forged vs. legitimate DNS responses.

#### Forged vs. Legitimate Comparison

| Property | Forged (198.51.100.1) | Legitimate (1.1.1.1) |
|---|---|---|
| `aa` (Authoritative Answer) flag | **True** | False |
| `rd` (Recursion Desired) | False (stripped) | True |
| `ra` (Recursion Available) | False | True |
| Raw flags | `0x8400` (qr+aa only) | `0x8180` (qr+rd+ra) |
| TTL | 10s (always) | 235s+ (varies) |
| EDNS/OPT record | Absent | Present |
| Answer count | 1 | 1+ |
| Query ID | Echoed from client | Echoed from client |

#### Record-Type Behavior

| Query Type | Response | Notes |
|---|---|---|
| A | Forged → `49.205.75.11` | Normal forged response |
| AAAA | **Malformed packet** | Interceptor sends A-record bytes for AAAA query |
| CNAME | **Malformed packet** | Same malformation |
| MX | No response (timeout) | Not intercepted — passes through |
| TXT | No response (timeout) | Not intercepted |
| NS | No response (timeout) | Not intercepted |
| SOA | No response (timeout) | Not intercepted |

The interceptor only knows how to forge A-record responses. AAAA and CNAME queries produce **malformed packets** (it sends A-record rdata regardless of the query type), while all other query types pass through unintercepted.

---

### 6. Matching-Rule Analysis

**Script:** `scripts/06_matching_rules.py`
**Evidence:** `evidence/06_matching_rules.json`

Tests the interceptor's domain-matching logic to understand how the blocklist works.

| Test | Domain | Result | Inference |
|---|---|---|---|
| Exact match | `youtube.com` | Intercepted | Base domain blocked |
| Case upper | `YOUTUBE.COM` | Intercepted | Case-insensitive |
| Mixed case | `Youtube.Com` | Intercepted | Case-insensitive |
| Trailing dot | `youtube.com.` | Intercepted | FQDN normalized |
| Random subdomain | `random123.youtube.com` | Intercepted | **Wildcard `*.youtube.com` blocked** |
| Deep subdomain | `deep.sub.youtube.com` | Intercepted | Wildcard matches at any depth |
| Whitelisted | `www.youtube.com` | **NOT intercepted** | **Explicitly exempted** |
| Whitelisted | `m.youtube.com` | **NOT intercepted** | **Explicitly exempted** |
| Sub of whitelisted | `random123.www.youtube.com` | NOT intercepted | Exemption covers children |
| Suffix attack | `notyoutube.com` | NOT intercepted | Not substring matching |
| Prefix attack | `youtube.com.evil.com` | NOT intercepted | Not naive prefix matching |
| Mid-domain | `evil.youtube.com.evil.com` | NOT intercepted | Proper suffix matching only |

**Deduced matching rules:**

1. **Suffix/wildcard matching:** Blocking `youtube.com` blocks all `*.youtube.com` subdomains at any depth.
2. **Whitelist exemptions:** Specific subdomains like `www.youtube.com` and `m.youtube.com` are explicitly exempted from the wildcard block (but still blocked at HTTP level).
3. **Case-insensitive:** `YOUTUBE.COM` is treated the same as `youtube.com`.
4. **Proper suffix matching:** Not fooled by substring or prefix tricks (`notyoutube.com` passes through).
5. **Trailing dot normalization:** `youtube.com.` matches `youtube.com`.

---

## Key Discoveries Beyond the Initial Report

The initial report documented the core DNS interception. This investigation uncovered:

1. **The interception is UDP-only.** TCP-53, DoT (port 853), and DoH (port 443) all bypass it completely. This was not documented in the original report.

2. **The blocklist is curated, not blanket.** 49 specific domains are blocked out of 170 tested. Random/nonexistent domains pass through. The blocking is targeted.

3. **Four distinct legal-authority categories** are cited on the HTTP blockpage, revealing that ACT implements blocks under different legal instruments: Court Orders, Government Authority directives, Law Enforcement Agency notices, and MeitY/IT Act orders.

4. **The HTTP blocklist is larger than the DNS blocklist.** `www.youtube.com` and `m.youtube.com` are not DNS-blocked but are HTTP-blocked. This proves two independent blocking layers.

5. **The sinkhole is a transparent HTTP proxy.** The same server that serves blockpages also forwards non-blocked Host headers to real upstream servers, leaking its proxy functionality.

6. **Wildcard blocking with whitelist exemptions.** `*.youtube.com` is blocked, but `www.youtube.com` and `m.youtube.com` are explicitly exempted at the DNS level.

7. **Only A records are forged.** AAAA and CNAME queries produce malformed packets (the interceptor sends A-record data regardless of query type). MX, TXT, NS, and SOA queries are not intercepted at all.

8. **The `aa` flag is always set** in forged responses, and `rd`/`ra` flags are stripped — producing flags of `0x8400` instead of the legitimate `0x8180`.

9. **Infrastructure header leaks.** The sinkhole exposes `X-Bg-Hostname: bgact-bangalore1`, tenant IDs, rate-limit headers, and the client's real IP address.

10. **The sinkhole IP (`49.205.75.11`)** is confirmed ACT infrastructure via WHOIS (AS24309, ACT Fibernet / Beam Telecom Pvt Ltd) and reverse DNS (`broadband.actcorp.in`).

---

## Technical Violations

### RFC Violations

| Standard | Violation |
|---|---|
| **RFC 1035** (DNS) | Forged responses set the `aa` (Authoritative Answer) flag while impersonating recursive resolvers — a procedural impossibility |
| **RFC 5737** (TEST-NET) | Responses are generated for queries to non-routable documentation IPs, proving packets never reach the internet |
| **RFC 768** (UDP) | UDP datagrams are intercepted and modified in-transit, breaking the datagram delivery model |
| **RFC 7858** (DoT) | Not violated — DoT bypasses interception, proving the proxy only handles plaintext UDP |
| **RFC 8484** (DoH) | Not violated — DoH bypasses interception for the same reason |

### End-to-End Principle Violation

By intercepting Layer 4 UDP transport payloads destined for external autonomous systems, the network breaks end-to-end IP routing integrity. Packets addressed to one destination (e.g., 1.1.1.1) are answered by a different entity (ACT's interceptor), with the response crafted to appear as if it came from the original destination.

### Packet Forgery

Injecting false answers while claiming the identity of third-party IP addresses constitutes deliberate packet forgery. The interceptor:
- Copies the client's query transaction ID
- Sets the source IP to the destination the client specified
- Constructs a syntactically valid DNS response with false resource records

---

## Repository Structure

```
act-transparent-proxy-bans/
├── scripts/
│   ├── 01_raw_udp_interception.py   # Core proof: raw UDP queries to non-routable IPs
│   ├── 02_blocklist_scan.py          # Scan 170 domains for DNS blocking
│   ├── 03_blockpage_messages.py      # HTTP blockpage legal-category analysis
│   ├── 04_transport_bypass.py        # TCP/DoT/DoH bypass demonstration
│   ├── 05_packet_forensics.py        # Wire-format packet dissection
│   └── 06_matching_rules.py          # Blocklist matching-logic analysis
├── evidence/                         # JSON output from each script run
│   ├── 01_raw_udp_interception.json
│   ├── 02_blocklist_scan.json
│   ├── 03_blockpage_messages.json
│   ├── 04_transport_bypass.json
│   ├── 05_packet_forensics.json
│   └── 06_matching_rules.json
├── pyproject.toml
├── run_all.sh                        # Run all scripts in sequence
└── README.md
```

---

## Reproducibility

All evidence in this repository was collected on **2026-07-13** from a machine on the ACT Fibernet network (AS24309). To reproduce:

1. Connect to the ACT Fibernet network.
2. Clone this repository.
3. Run `./run_all.sh` (requires `uv`).
4. Compare your `evidence/` output with the committed results.

The blocking behavior may change over time as ACT updates its blocklists or infrastructure. The scripts are designed to capture the current state for comparison.
