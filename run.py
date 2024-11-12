#!/usr/bin/env python3
import logging
import json
# Suppress Wireshark warning
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)

from network_sentinel.main import NetworkSentinel
from network_sentinel.config import NetworkSentinelConfig

if __name__ == "__main__":
    config = NetworkSentinelConfig()
    sentinel = NetworkSentinel(config)
    try:
        print("""
╔═══════════════════════════════════════════════╗
║         Network Sentinel - Version 2.0         ║
║     Advanced Network Security Monitoring       ║
║                                               ║
║        Created by D3F417 (Beta Release)       ║
║            RastaKhiz Team © 2024             ║
╚═══════════════════════════════════════════════╝
        """)
        sentinel.start_monitoring()
    except KeyboardInterrupt:
        sentinel.running = False
        print("\nStopping Network Sentinel...")
        # Save final statistics
        with open('stats.json', 'w') as f:
            json.dump(sentinel.stats, f, indent=4) 
