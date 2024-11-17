import scapy.all as scapy
from collections import deque, defaultdict
import time
import numpy as np
import logging
import threading
from threading import Lock

class PacketAnalyzer:
    def __init__(self):
        # Updated thresholds
        self.syn_flood_threshold = 150  # Increased from 100
        self.udp_flood_threshold = 1200  # Increased from 1000
        self.icmp_flood_threshold = 75   # Increased from 50
        
        # New cleanup configuration
        self.cleanup_interval = 180  # Reduced from 300
        self.max_history_size = 5000  # Reduced from 10000
        
        # Add thread safety
        self._lock = threading.Lock()
        
        # Enhanced thresholds and configuration
        self.port_scan_window = 60  # Time window in seconds
        self.packet_history = deque(maxlen=10000)
        self.last_packet_times = {}
        self.syn_count = {}
        self.scan_detection = {
            'window_size': 60,  # 60 seconds window
            'port_threshold': 15,  # Number of unique ports to trigger alert
            'syn_ratio_threshold': 0.8,  # Ratio of SYN to total packets
            'history': defaultdict(lambda: {
                'ports': set(),
                'syn_count': 0,
                'total_count': 0,
                'last_reset': time.time()
            })
        }
        self.ack_scan_detection = {
            'window_size': 30,  # 30 seconds window
            'port_threshold': 10,  # Number of unique ports for ACK scan
            'history': defaultdict(lambda: {
                'ports': set(),
                'last_reset': time.time()
            })
        }
        
        # Add cleanup timers
        self.last_cleanup = time.time()
        self.cleanup_interval = 300  # 5 minutes
        self.max_history_size = 10000
        
        # Add thread safety
        self.lock = Lock()
        
    def analyze_packet(self, packet):
        """
        Analyzes a packet and returns (threat_level, threat_type)
        threat_level: 0 (normal), 1 (suspicious), 2 (dangerous), 3 (critical)
        """
        threat_level = 0
        threat_type = None

        if packet.haslayer(scapy.IP):
            # Check for TTL anomalies
            if packet[scapy.IP].ttl < 10:
                return 1, "Suspicious TTL Value"

            # Check for fragmentation
            if packet[scapy.IP].flags == 1:  # More fragments
                return 2, "Fragmentation Attack"

            # TCP analysis
            if packet.haslayer(scapy.TCP):
                threat_level, threat_type = self.analyze_tcp_behavior(packet)
            
            # UDP analysis
            elif packet.haslayer(scapy.UDP):
                threat_level, threat_type = self.analyze_udp_behavior(packet)

        return threat_level, threat_type

    def analyze_tcp_behavior(self, packet):
        """Enhanced TCP behavior analysis"""
        src_ip = packet[scapy.IP].src
        flags = packet[scapy.TCP].flags
        
        # Advanced scan detection
        scan_type = self.detect_scan_type(packet)
        if scan_type:
            return 2, f"{scan_type} Detected"
            
        # SYN flood detection with improved accuracy
        if self.detect_syn_flood(src_ip, packet):
            return 3, "SYN Flood Attack"
            
        # TCP connection analysis
        if self.analyze_tcp_connection(packet):
            return 2, "Suspicious TCP Behavior"
            
        return 0, None

    def analyze_udp_behavior(self, packet):
        """Analyze UDP packet behavior for threats"""
        src_ip = packet[scapy.IP].src
        
        # Check for UDP flood
        if self.detect_udp_flood(src_ip):
            return 3, "UDP Flood Attack"
            
        # Check for DNS amplification
        if packet.haslayer(scapy.UDP) and packet[scapy.UDP].dport == 53:
            if len(packet) > 512:  # Large DNS packet
                return 2, "Potential DNS Amplification"
                
        return 0, None

    def detect_syn_flood(self, src_ip, packet):
        """Detect SYN flood attacks with improved accuracy"""
        try:
            current_time = time.time()
            
            if src_ip not in self.syn_count:
                self.syn_count[src_ip] = {'count': 1, 'first_seen': current_time}
            else:
                self.syn_count[src_ip]['count'] += 1
                
                # Check if we've seen too many SYN packets in a short time
                elapsed_time = current_time - self.syn_count[src_ip]['first_seen']
                if elapsed_time < 1 and self.syn_count[src_ip]['count'] > self.syn_flood_threshold:
                    return True
                    
                # Reset counter if too much time has passed
                if elapsed_time > 1:
                    self.syn_count[src_ip] = {'count': 1, 'first_seen': current_time}
                    
            return False
            
        except Exception as e:
            logging.error(f"Error in SYN flood detection: {str(e)}")
            return False

    def extract_features(self, packet):
        """Extract features for machine learning analysis"""
        features = []
        
        if packet.haslayer(scapy.IP):
            features.extend([
                packet[scapy.IP].len,
                packet[scapy.IP].ttl,
                len(packet),
                1 if packet.haslayer(scapy.TCP) else 0,
                1 if packet.haslayer(scapy.UDP) else 0,
                1 if packet.haslayer(scapy.ICMP) else 0
            ])
        else:
            features.extend([0, 0, len(packet), 0, 0, 0])
            
        return np.array(features) 

    def detect_udp_flood(self, src_ip):
        """Detect UDP flood attacks"""
        current_time = time.time()
        
        if src_ip not in self.last_packet_times:
            self.last_packet_times[src_ip] = {'time': current_time, 'count': 1}
            return False
        
        elapsed = current_time - self.last_packet_times[src_ip]['time']
        if elapsed < 1:  # Within 1 second
            self.last_packet_times[src_ip]['count'] += 1
            if self.last_packet_times[src_ip]['count'] > 1000:  # Threshold for UDP flood
                return True
        else:
            self.last_packet_times[src_ip] = {'time': current_time, 'count': 1}
        
        return False

    def detect_icmp_flood(self, src_ip):
        """Detect ICMP flood attacks"""
        current_time = time.time()
        
        if src_ip not in self.last_packet_times:
            self.last_packet_times[src_ip] = {'time': current_time, 'count': 1}
            return False
        
        elapsed = current_time - self.last_packet_times[src_ip]['time']
        if elapsed < 1:  # Within 1 second
            self.last_packet_times[src_ip]['count'] += 1
            if self.last_packet_times[src_ip]['count'] > 100:  # Threshold for ICMP flood
                return True
        else:
            self.last_packet_times[src_ip] = {'time': current_time, 'count': 1}
        
        return False

    def detect_scan_type(self, packet):
        """Detect various types of port scans"""
        flags = packet[scapy.TCP].flags
        
        # NULL scan (no flags)
        if flags == 0:
            return "NULL Scan"
            
        # FIN scan (only FIN flag)
        if flags == 0x01:
            return "FIN Scan"
            
        # XMAS scan (FIN, PSH, URG flags)
        if flags == 0x29:
            return "XMAS Scan"
            
        # SYN scan detection with improved accuracy
        if self.detect_syn_scan(packet):
            return "SYN Scan"
            
        # ACK scan detection
        if flags == 0x10 and self.detect_ack_scan(packet):
            return "ACK Scan"
            
        return None

    def detect_syn_scan(self, packet):
        """Enhanced SYN scan detection"""
        src_ip = packet[scapy.IP].src
        current_time = time.time()
        scan_info = self.scan_detection['history'][src_ip]
        
        # Reset counters if window expired
        if current_time - scan_info['last_reset'] > self.scan_detection['window_size']:
            scan_info['ports'] = set()
            scan_info['syn_count'] = 0
            scan_info['total_count'] = 0
            scan_info['last_reset'] = current_time
        
        # Update statistics
        scan_info['total_count'] += 1
        if packet[scapy.TCP].flags & 0x02:  # SYN flag
            scan_info['syn_count'] += 1
        scan_info['ports'].add(packet[scapy.TCP].dport)
        
        # Check for scan patterns
        if (len(scan_info['ports']) > self.scan_detection['port_threshold'] and
            scan_info['syn_count'] / scan_info['total_count'] > self.scan_detection['syn_ratio_threshold']):
            return True
            
        return False

    def analyze_tcp_connection(self, packet):
        """Analyze TCP connection patterns"""
        src_ip = packet[scapy.IP].src
        dst_port = packet[scapy.TCP].dport
        
        # Updated suspicious ports list
        suspicious_ports = {
            4444,  # Metasploit
            1433,  # SQL Server
            3389,  # RDP
            445,   # SMB
            135,   # RPC
            22,    # SSH
            23,    # Telnet
            6666,  # Added: IRC
            8080,  # Added: Alternative HTTP
            9001   # Added: Common backdoor
        }
        
        if dst_port in suspicious_ports:
            return True
            
        return False

    def detect_ack_scan(self, packet):
        """Detect ACK scan attempts"""
        try:
            src_ip = packet[scapy.IP].src
            current_time = time.time()
            scan_info = self.ack_scan_detection['history'][src_ip]
            
            # Reset if window expired
            if current_time - scan_info['last_reset'] > self.ack_scan_detection['window_size']:
                scan_info['ports'] = set()
                scan_info['last_reset'] = current_time
            
            # Add port to set
            scan_info['ports'].add(packet[scapy.TCP].dport)
            
            # Check if number of unique ports exceeds threshold
            if len(scan_info['ports']) > self.ack_scan_detection['port_threshold']:
                return True
                
            return False
            
        except Exception as e:
            logging.error(f"Error in ACK scan detection: {str(e)}")
            return False

    def cleanup_old_data(self):
        """Periodic cleanup of old data"""
        current_time = time.time()
        if current_time - self.last_cleanup < self.cleanup_interval:
            return
            
        with self.lock:
            # Cleanup scan detection history
            for ip in list(self.scan_detection['history'].keys()):
                if current_time - self.scan_detection['history'][ip]['last_reset'] > self.scan_detection['window_size'] * 2:
                    del self.scan_detection['history'][ip]
                    
            # Cleanup ACK scan history
            for ip in list(self.ack_scan_detection['history'].keys()):
                if current_time - self.ack_scan_detection['history'][ip]['last_reset'] > self.ack_scan_detection['window_size'] * 2:
                    del self.ack_scan_detection['history'][ip]
                    
            # Cleanup SYN count data
            for ip in list(self.syn_count.keys()):
                if current_time - self.syn_count[ip]['first_seen'] > 60:
                    del self.syn_count[ip]
                    
            self.last_cleanup = current_time
