import pytest
from network_sentinel.config import NetworkSentinelConfig
from pathlib import Path

def test_config_loading():
    config = NetworkSentinelConfig()
    assert hasattr(config, 'syn_flood_threshold')
    assert hasattr(config, 'log_level')
    assert config.syn_flood_threshold == 100  # default value

def test_config_from_file(tmp_path):
    config_file = tmp_path / "test_config.yaml"
    config_file.write_text("""
syn_flood_threshold: 200
log_level: "DEBUG"
    """)
    config = NetworkSentinelConfig.load(str(config_file))
    assert config.syn_flood_threshold == 200
    assert config.log_level == "DEBUG" 
