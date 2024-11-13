import pytest
from network_sentinel.utils.secure_storage import SecureStorage
import os
import json

def test_secure_storage(tmp_path):
    # Set up a temporary directory for testing
    os.environ['TEST_MODE'] = 'true'
    storage = SecureStorage(key_dir=tmp_path)
    
    # Test encryption/decryption
    test_data = {"key": "value"}
    encrypted = storage.encrypt_data(test_data)
    decrypted = storage.decrypt_data(encrypted)
    assert decrypted == test_data

    # Test key file creation
    key_file = tmp_path / '.key'
    assert key_file.exists()
    assert os.stat(key_file).st_mode & 0o777 == 0o600 
