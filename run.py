#!/usr/bin/env python3
import logging
import json
import sys
import os
from rich.console import Console
from rich.panel import Panel

# Configure logging before imports
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
logging.getLogger('scapy.loading').setLevel(logging.ERROR)

# Create .scapy directory if it doesn't exist
scapy_dir = os.path.expanduser('~/.scapy')
os.makedirs(scapy_dir, exist_ok=True)

# Create empty manuf file if it doesn't exist
manuf_file = os.path.join(scapy_dir, 'manuf')
if not os.path.exists(manuf_file):
    open(manuf_file, 'a').close()

from network_sentinel.main import NetworkSentinel
from network_sentinel.config import NetworkSentinelConfig
from network_sentinel.utils.security_checks import SecurityChecker

console = Console()

def verify_admin():
    """Check if running with admin privileges"""
    try:
        if os.name == 'nt':  # Windows
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:  # Unix-like
            return os.geteuid() == 0
    except:
        return False

if __name__ == "__main__":
    try:
        # Check admin privileges
        if not verify_admin():
            console.print(Panel.fit(
                "[red]Error: Administrator privileges required[/red]\n"
                "Please run as administrator (Windows) or with sudo (Linux)",
                title="Error"
            ))
            sys.exit(1)

        # Initialize security checker
        security = SecurityChecker()
        if not security.verify_dependencies():
            sys.exit(1)

        config = NetworkSentinelConfig()
        sentinel = NetworkSentinel(config)
        
        console.print("""
╔═══════════════════════════════════════════════╗
║         Network Sentinel - Version 2.1         ║
║     Advanced Network Security Monitoring       ║
║                                               ║
║        Created by D3F417 (Beta Release)       ║
║            RastaKhiz Team © 2024             ║
╚═══════════════════════════════════════════════╝
        """)
        
        sentinel.start_monitoring()
        
    except KeyboardInterrupt:
        sentinel.running = False
        console.print("\nStopping Network Sentinel...")
        with open('stats.json', 'w') as f:
            json.dump(sentinel.stats, f, indent=4)
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        logging.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1) 
