#!/usr/bin/env bash
# Run all investigation scripts in sequence and collect evidence.
set -e
cd "$(dirname "$0")/.."

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ACT Transparent DNS Proxy Investigation — Full Suite       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo

for script in scripts/01_raw_udp_interception.py \
             scripts/02_blocklist_scan.py \
             scripts/03_blockpage_messages.py \
             scripts/04_transport_bypass.py \
             scripts/05_packet_forensics.py \
             scripts/06_matching_rules.py; do
    echo "▶ Running $script..."
    echo "────────────────────────────────────────────────────────────"
    uv run "$script"
    echo
done

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  All scripts complete. Evidence in ./evidence/               ║"
echo "╚══════════════════════════════════════════════════════════════╝"
ls -lh evidence/
