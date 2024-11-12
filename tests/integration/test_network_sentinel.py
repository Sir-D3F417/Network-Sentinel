import pytest
from network_sentinel.main import NetworkSentinel
from network_sentinel.config import NetworkSentinelConfig

@pytest.fixture
def sentinel():
    config = NetworkSentinelConfig()
    return NetworkSentinel(config)

def test_sentinel_initialization(sentinel):
    assert hasattr(sentinel, 'packet_analyzer')
    assert hasattr(sentinel, 'threat_detector')
    assert hasattr(sentinel, 'running') 