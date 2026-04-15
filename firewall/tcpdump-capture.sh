#!/bin/bash
# Capture packets on honeypot ports, rotate daily, cap at 1GB per file
PCAP_DIR="/opt/honeypot/pcap"
mkdir -p "$PCAP_DIR"

# Capture only honeypot ports
tcpdump -i eth0 \
  'port 80 or port 1883 or port 502 or port 102 or port 47808' \
  -w "$PCAP_DIR/honeypot_%Y%m%d_%H%M%S.pcap" \
  -G 86400 \
  -C 1000 \
  -Z root
