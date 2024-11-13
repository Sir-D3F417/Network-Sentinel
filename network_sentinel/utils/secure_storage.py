from cryptography.fernet import Fernet
import base64
import os
import json
import logging
from pathlib import Path

class SecureStorage:
    def __init__(self, key_dir=None):
        self.logger = logging.getLogger(__name__)
        if key_dir:
            self.key_file = Path(key_dir) / '.key'
        else:
            self.key_file = Path('./config/.key')
        self.key = self._load_or_create_key()
        self.fernet = Fernet(self.key)

    def _load_or_create_key(self):
        """Load existing or create new encryption key"""
        try:
            if self.key_file.exists():
                with open(self.key_file, 'rb') as f:
                    return f.read()
            else:
                key = Fernet.generate_key()
                self.key_file.parent.mkdir(exist_ok=True)
                with open(self.key_file, 'wb') as f:
                    f.write(key)
                os.chmod(self.key_file, 0o600)
                return key
        except Exception as e:
            self.logger.error(f"Error handling encryption key: {e}")
            raise

    def encrypt_data(self, data):
        """Encrypt sensitive data"""
        try:
            json_data = json.dumps(data)
            return self.fernet.encrypt(json_data.encode())
        except Exception as e:
            self.logger.error(f"Encryption error: {e}")
            raise

    def decrypt_data(self, encrypted_data):
        """Decrypt sensitive data"""
        try:
            decrypted_data = self.fernet.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode())
        except Exception as e:
            self.logger.error(f"Decryption error: {e}")
            raise 
