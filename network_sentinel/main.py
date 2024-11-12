#!/usr/bin/env python3

import scapy.all as scapy
from collections import defaultdict, deque
import datetime
import pandas as pd
import threading
import logging
import time
import sys
import json
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from rich.panel import Panel
from rich.layout import Layout
import ipaddress
from rich import box
from rich.live import Live
import os

# Change relative imports to absolute
from network_sentinel.threat_detector import ThreatDetector
from network_sentinel.packet_analyzer import PacketAnalyzer
from network_sentinel.utils.security_checks import SecurityChecker
from network_sentinel.utils.secure_storage import SecureStorage
from .config import NetworkSentinelConfig

class SecurityError(Exception):
    """Custom exception for security-related errors"""
    pass

class NetworkSentinel:
    def __init__(self, config):
        self.security = SecurityChecker()
        self.secure_storage = SecureStorage()
        
        # Perform security checks before initialization
        if not self._perform_security_checks():
            raise SecurityError("Security checks failed")
            
        self.packet_counts = defaultdict(int)
        self.suspicious_ips = set()
        self.port_scan_threshold = 100
        self.port_scan_counter = defaultdict(lambda: defaultdict(int))
        self.console = Console(color_system="truecolor")
        self.threat_detector = ThreatDetector()
        self.packet_analyzer = PacketAnalyzer()
        self.last_packet_times = {}
        self.setup_logging()
        self.running = True
        self.stats = {
            'total_packets': 0,
            'suspicious_packets': 0,
            'protocols': defaultdict(int),
            'top_talkers': defaultdict(int),
            'attack_types': defaultdict(int)
        }
        self.load_known_threats()
        self.threat_buffer = deque(maxlen=10)  # Increase buffer size slightly
        self.display_update_interval = 1  # Add refresh rate control
        self.live_display = None
        self.threat_cooldown = {}  # Track last alert time per IP
        self.cooldown_period = 5  # Seconds between alerts for same IP/reason
        self.consolidated_threats = defaultdict(lambda: {
            'count': 0,
            'first_seen': None,
            'last_seen': None,
            'level': 0
        })

    def load_known_threats(self):
        try:
            with open('known_threats.json', 'r') as f:
                self.known_threats = json.load(f)
        except FileNotFoundError:
            self.known_threats = {
                'malicious_ips': [],
                'suspicious_ports': [22, 23, 3389, 445],
                'attack_signatures': {}
            }

    def setup_logging(self):
        logging.basicConfig(
            filename='network_sentinel.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        # Add console handler for immediate feedback
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)
        logging.getLogger('').addHandler(console_handler)

    def packet_callback(self, packet):
        """Process each captured packet"""
        try:
            # Skip non-IP packets
            if not packet.haslayer(scapy.IP):
                return

            # Extract basic packet info
            src_ip = packet[scapy.IP].src
            
            # Update basic statistics
            self.packet_counts[src_ip] += 1
            self.stats['total_packets'] += 1
            
            # Update protocol statistics
            if packet.haslayer(scapy.TCP):
                self.stats['protocols']['TCP'] += 1
                self.analyze_tcp_packet(packet)
            elif packet.haslayer(scapy.UDP):
                self.stats['protocols']['UDP'] += 1
                self.analyze_udp_packet(packet)
            elif packet.haslayer(scapy.ICMP):
                self.stats['protocols']['ICMP'] += 1
                self.analyze_icmp_packet(packet)

            # Extract features for ML analysis
            features = self.packet_analyzer.extract_features(packet)
            
            # Check for anomalies using ML model
            if self.threat_detector.is_anomalous(features):
                self.handle_threat(src_ip, None, "ML-detected anomaly", 2)
                self.stats['suspicious_packets'] += 1

            # Basic threat analysis
            threat_level, threat_type = self.packet_analyzer.analyze_packet(packet)
            if threat_level > 0:
                self.handle_threat(src_ip, None, threat_type, threat_level)
                self.stats['suspicious_packets'] += 1

            # Update top talkers
            self.stats['top_talkers'][src_ip] = self.packet_counts[src_ip]

        except Exception as e:
            logging.error(f"Error processing packet: {str(e)}")

    def analyze_tcp_packet(self, packet):
        """Analyze TCP packets for threats"""
        try:
            src_ip = packet[scapy.IP].src
            dst_port = packet[scapy.TCP].dport
            flags = packet[scapy.TCP].flags

            # Check for port scanning
            self.port_scan_counter[src_ip][dst_port] += 1
            if len(self.port_scan_counter[src_ip]) > self.port_scan_threshold:
                self.handle_threat(src_ip, None, "Port Scanning", 2)

            # Check for suspicious ports
            if dst_port in self.known_threats['suspicious_ports']:
                self.handle_threat(src_ip, None, f"Access to suspicious port {dst_port}", 1)

        except Exception as e:
            logging.error(f"Error analyzing TCP packet: {str(e)}")

    def analyze_udp_packet(self, packet):
        """Analyze UDP packets for threats"""
        try:
            src_ip = packet[scapy.IP].src
            dst_port = packet[scapy.UDP].dport

            # Check for DNS amplification
            if dst_port == 53 and len(packet) > 512:
                self.handle_threat(src_ip, None, "Potential DNS Amplification", 2)

            # Check for suspicious ports
            if dst_port in self.known_threats['suspicious_ports']:
                self.handle_threat(src_ip, None, f"Access to suspicious port {dst_port}", 1)

        except Exception as e:
            logging.error(f"Error analyzing UDP packet: {str(e)}")

    def analyze_icmp_packet(self, packet):
        """Analyze ICMP packets for threats"""
        try:
            src_ip = packet[scapy.IP].src

            # Check for ICMP flood
            if self.packet_analyzer.detect_icmp_flood(src_ip):
                self.handle_threat(src_ip, None, "ICMP Flood Attack", 3)

            # Check for suspicious packet sizes
            if len(packet) > 1000:
                self.handle_threat(src_ip, None, "Suspicious ICMP Packet Size", 2)

        except Exception as e:
            logging.error(f"Error analyzing ICMP packet: {str(e)}")

    def handle_threat(self, src_ip, dst_ip=None, reason="Unknown", threat_level=1):
        """Handle detected threats"""
        try:
            self.suspicious_ips.add(src_ip)
            self.log_threat(src_ip, reason, threat_level)
            
            # Update attack statistics
            if reason not in self.stats['attack_types']:
                self.stats['attack_types'][reason] = 0
            self.stats['attack_types'][reason] += 1

        except Exception as e:
            logging.error(f"Error handling threat: {str(e)}")

    def create_status_display(self):
        """Create the main display layout"""
        try:
            # Create main layout
            layout = Layout()
            layout.split_column(
                Layout(name="header", size=3),
                Layout(name="body"),
                Layout(name="footer", size=3)
            )

            # Header
            header = Panel(
                "[bold cyan]Network Sentinel - Real-time Security Monitor[/bold cyan]",
                style="cyan",
                box=box.ROUNDED
            )
            layout["header"].update(header)

            # Body layout
            body_layout = Layout()
            body_layout.split_row(
                Layout(name="main", ratio=2),
                Layout(name="side", ratio=1)
            )

            # Main section (traffic and threats)
            main_layout = Layout()
            main_layout.split_column(
                Layout(name="traffic"),
                Layout(name="threats", ratio=1)
            )
            main_layout["traffic"].update(self.create_main_table())
            main_layout["threats"].update(self.create_threats_table())
            body_layout["main"].update(main_layout)

            # Side section (stats)
            side_layout = Layout()
            side_layout.split_column(
                Layout(name="stats"),
                Layout(name="protocols")
            )
            side_layout["stats"].update(self.create_stats_table())
            side_layout["protocols"].update(self.create_protocol_table())
            body_layout["side"].update(side_layout)

            layout["body"].update(body_layout)

            # Footer
            footer = Panel(
                f"[bold green]Active Monitoring[/bold green] | "
                f"Packets: {self.stats['total_packets']} | "
                f"Threats: {self.stats['suspicious_packets']} | "
                "Press Ctrl+C to exit",
                style="green",
                box=box.ROUNDED
            )
            layout["footer"].update(footer)

            return layout

        except Exception as e:
            logging.error(f"Error creating display: {str(e)}")
            return Panel("[red]Error creating display[/red]")

    def create_main_table(self):
        """Create the main traffic analysis table"""
        try:
            table = Table(
                title="Network Traffic Analysis",
                show_header=True,
                header_style="bold magenta",
                box=box.DOUBLE_EDGE
            )
            
            table.add_column("IP Address", style="cyan", width=20)
            table.add_column("Packet Count", style="magenta", justify="right")
            table.add_column("Status", style="green", width=15)
            table.add_column("Threat Level", style="red", width=12)
            table.add_column("Last Activity", style="yellow", width=12)

            # Add data rows
            sorted_ips = sorted(self.packet_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            for ip, count in sorted_ips:
                threat_level = "High" if ip in self.suspicious_ips else "Low"
                status = "🚨 Suspicious" if ip in self.suspicious_ips else "✅ Normal"
                last_activity = datetime.datetime.now().strftime("%H:%M:%S")
                table.add_row(str(ip), str(count), status, threat_level, last_activity)
            
            return table
        except Exception as e:
            logging.error(f"Error creating main table: {str(e)}")
            return Table(title="Error loading data")

    def create_stats_table(self):
        """Create the statistics table"""
        try:
            table = Table(title="Security Statistics", box=box.SIMPLE)
            table.add_column("Metric", style="blue")
            table.add_column("Value", style="green", justify="right")
            
            table.add_row("Total Packets", str(self.stats['total_packets']))
            table.add_row("Suspicious Packets", str(self.stats['suspicious_packets']))
            table.add_row("Active Threats", str(len(self.suspicious_ips)))
            
            return table
        except Exception as e:
            logging.error(f"Error creating stats table: {str(e)}")
            return Table(title="Error loading stats")

    def create_protocol_table(self):
        """Create the protocol statistics table"""
        try:
            table = Table(title="Protocol Statistics", box=box.SIMPLE)
            table.add_column("Protocol", style="blue")
            table.add_column("Count", style="green", justify="right")
            
            for protocol, count in self.stats['protocols'].items():
                table.add_row(protocol, str(count))
            
            return table
        except Exception as e:
            logging.error(f"Error creating protocol table: {str(e)}")
            return Table(title="Error loading protocols")

    def create_threats_table(self):
        """Create table of recent threats with consolidated view"""
        try:
            table = Table(
                show_header=True,
                header_style="bold red",
                box=box.ROUNDED,
                title="[bold red]Active Threats[/bold red]",
                padding=(0, 1),
                collapse_padding=True
            )
            
            table.add_column("Time", style="yellow", width=8)
            table.add_column("IP Address", style="cyan", width=15)
            table.add_column("Threat Type", style="red", width=35)
            table.add_column("Level", style="magenta", justify="center", width=6)
            
            # Show only unique threats in the last period
            seen_threats = set()
            for threat in list(self.threat_buffer)[:8]:
                threat_key = f"{threat['ip']}:{threat['reason']}"
                if threat_key not in seen_threats:
                    seen_threats.add(threat_key)
                    table.add_row(
                        threat['timestamp'],
                        threat['ip'],
                        threat['reason'],
                        f"[bold red]{threat['level']}[/bold red]"
                    )
                
            return table
        except Exception as e:
            logging.error(f"Error creating threats table: {str(e)}")
            return Table(title="Error loading threats")

    def display_stats(self):
        """Display network statistics in real-time"""
        try:
            with Live(self.create_status_display(), refresh_per_second=1) as live:
                self.live_display = live
                while self.running:
                    try:
                        live.update(self.create_status_display())
                        time.sleep(self.display_update_interval)
                    except Exception as e:
                        logging.error(f"Error updating display: {str(e)}")
                        time.sleep(1)
        except Exception as e:
            logging.error(f"Fatal error in display_stats: {str(e)}")

    def is_private_ip(self, ip):
        return ipaddress.ip_address(ip).is_private

    def is_public_ip(self, ip):
        return not ipaddress.ip_address(ip).is_private

    def log_threat(self, ip, reason, threat_level=1, extra_info=None):
        """Log threats with cooldown and consolidation"""
        try:
            current_time = time.time()
            threat_key = f"{ip}:{reason}"

            # Check cooldown period
            if threat_key in self.threat_cooldown:
                if current_time - self.threat_cooldown[threat_key] < self.cooldown_period:
                    # Update consolidated count silently
                    self.consolidated_threats[threat_key]['count'] += 1
                    self.consolidated_threats[threat_key]['last_seen'] = current_time
                    return
            
            # Update cooldown and consolidated stats
            self.threat_cooldown[threat_key] = current_time
            
            if threat_key not in self.consolidated_threats:
                self.consolidated_threats[threat_key] = {
                    'count': 1,
                    'first_seen': current_time,
                    'last_seen': current_time,
                    'level': threat_level
                }
            
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            
            # Create consolidated message
            count = self.consolidated_threats[threat_key]['count']
            if count > 1:
                consolidated_reason = f"{reason} (Repeated {count} times)"
            else:
                consolidated_reason = reason

            # Add to threat buffer for display
            self.threat_buffer.appendleft({
                'timestamp': timestamp,
                'ip': ip,
                'reason': consolidated_reason,
                'level': threat_level
            })
            
            # Log to file with consolidated info
            logging.warning(
                f"THREAT - IP: {ip} - {consolidated_reason} - Level: {threat_level}"
            )
            
            # Update suspicious IPs set
            self.suspicious_ips.add(ip)
            
        except Exception as e:
            logging.error(f"Error logging threat: {str(e)}")

    def get_network_interface(self):
        try:
            # Alternative method for Windows
            if sys.platform == 'win32':
                from scapy.arch import get_windows_if_list
                interfaces = get_windows_if_list()
                
                self.console.print("\n[yellow]Available Network Interfaces:[/yellow]")
                for idx, iface in enumerate(interfaces):
                    self.console.print(f"{idx}: {iface['name']} ({iface['description']})")
            else:
                interfaces = scapy.get_if_list()
                self.console.print("\n[yellow]Available Network Interfaces:[/yellow]")
                for idx, iface in enumerate(interfaces):
                    self.console.print(f"{idx}: {iface}")

            while True:
                try:
                    choice = input("\nSelect interface number: ")
                    idx = int(choice)
                    if sys.platform == 'win32':
                        selected_iface = interfaces[idx]['name']
                    else:
                        selected_iface = interfaces[idx]
                    return selected_iface
                except (ValueError, IndexError):
                    print("Invalid selection. Please try again.")

        except Exception as e:
            logging.error(f"Error getting network interfaces: {str(e)}")
            raise RuntimeError(f"Failed to get network interfaces: {str(e)}")

    def start_monitoring(self, interface=None):
        try:
            if interface is None:
                interface = self.get_network_interface()

            # Start the display thread
            display_thread = threading.Thread(target=self.display_stats, daemon=True)
            display_thread.start()

            # Start packet capture
            self.console.print(f"[green]Starting network monitoring on interface: {interface}...[/green]")
            scapy.sniff(iface=interface, prn=self.packet_callback, store=False)

        except Exception as e:
            self.running = False
            self.console.print(f"[red]Error: {str(e)}[/red]")
            logging.error(f"Error in start_monitoring: {str(e)}")

    def _perform_security_checks(self):
        """Perform all security checks"""
        checks = [
            self.security.check_root_privileges(),
            self.security.check_file_permissions(),
            self.security.check_network_access(),
            self.security.validate_ml_models()
        ]
        return all(checks)

    def save_state(self):
        """Securely save application state"""
        state_data = {
            'stats': self.stats,
            'suspicious_ips': list(self.suspicious_ips),
            'ml_state': self.threat_detector.get_state()
        }
        encrypted_data = self.secure_storage.encrypt_data(state_data)
        with open('state.enc', 'wb') as f:
            f.write(encrypted_data)

    @staticmethod
    def list_interfaces():
        """List all available network interfaces"""
        console = Console()
        table = Table(title="Available Network Interfaces")
        
        table.add_column("Interface", style="cyan")
        table.add_column("Status", style="green")
        
        try:
            # Get all interfaces
            interfaces = scapy.get_if_list()
            
            for iface in interfaces:
                # Skip loopback on Linux
                if iface == "lo" and os.name != "nt":
                    continue
                    
                # Add to table
                table.add_row(iface, "Available")
                
            console.print(table)
            
        except Exception as e:
            console.print(f"[red]Error listing interfaces: {str(e)}[/red]")
            sys.exit(1)

def show_banner():
    return """
╔═══════════════════════════════════════════════╗
║         Network Sentinel - Version 2.0         ║
║     Advanced Network Security Monitoring       ║
║                                               ║
║        Created by D3F417 (Beta Release)       ║
║            RastaKhiz Team © 2024             ║
╚═══════════════════════════════════════════════╝
    """

if __name__ == "__main__":
    config = NetworkSentinelConfig.load()
    sentinel = NetworkSentinel(config)
    try:
        print(show_banner())
        sentinel.start_monitoring()
    except KeyboardInterrupt:
        sentinel.running = False
        print("\nStopping Network Sentinel...")
        # Save final statistics
        with open('session_stats.json', 'w') as f:
            json.dump(sentinel.stats, f, indent=4)
