import os
import sys
import pytest

# Add the project root directory to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

@pytest.fixture
def packet_analyzer():
    from network_sentinel.packet_analyzer import PacketAnalyzer
    return PacketAnalyzer()

@pytest.fixture
def threat_detector():
    from network_sentinel.threat_detector import ThreatDetector
    return ThreatDetector() 
