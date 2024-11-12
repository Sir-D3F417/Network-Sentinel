import pytest
from network_sentinel.utils.validation import validate_ip, validate_interface
from network_sentinel.utils.security import secure_file_permissions
import os

def test_validate_ip():
    assert validate_ip("192.168.1.1") == "192.168.1.1"
    assert validate_ip("256.256.256.256") is None
    assert validate_ip("invalid") is None

def test_validate_interface():
    assert validate_interface("eth0") == "eth0"
    assert validate_interface("wlan0") == "wlan0"
    with pytest.raises(ValueError):
        validate_interface("invalid/interface") 