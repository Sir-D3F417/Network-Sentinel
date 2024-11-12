import pytest
from network_sentinel.packet_analyzer import PacketAnalyzer

def test_packet_analyzer_init():
    analyzer = PacketAnalyzer()
    assert analyzer.syn_flood_threshold == 100
    assert analyzer.udp_flood_threshold == 1000
    assert analyzer.icmp_flood_threshold == 50 