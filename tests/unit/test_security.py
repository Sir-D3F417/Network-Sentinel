def test_secure_storage():
    storage = SecureStorage()
    test_data = {"key": "value"}
    encrypted = storage.encrypt_data(test_data)
    decrypted = storage.decrypt_data(encrypted)
    assert decrypted == test_data 
