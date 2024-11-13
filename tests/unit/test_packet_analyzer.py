def test_analyze_tcp_behavior():
    analyzer = PacketAnalyzer()
    # Create a mock TCP packet
    packet = IP(src="192.168.1.1")/TCP(flags="S")
    threat_level, threat_type = analyzer.analyze_tcp_behavior(packet)
    assert isinstance(threat_level, int)
    assert threat_type in ["SYN Flood", "Port Scan", None]

def test_detect_ack_scan():
    analyzer = PacketAnalyzer()
    packet = IP(src="192.168.1.1")/TCP(flags="A")
    result = analyzer.detect_ack_scan(packet)
    assert isinstance(result, bool) 
