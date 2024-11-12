import pytest
import sys
import os
from network_sentinel.packet_analyzer import PacketAnalyzer
import scapy.all as scapy

def test_packet_analyzer_init():
    analyzer = PacketAnalyzer()
    assert hasattr(analyzer, 'syn_flood_threshold')
    assert hasattr(analyzer, 'udp_flood_threshold')
    assert hasattr(analyzer, 'icmp_flood_threshold')

def test_scan_detection():
    analyzer = PacketAnalyzer()
    assert hasattr(analyzer, 'scan_detection')
    assert isinstance(analyzer.scan_detection, dict) 
