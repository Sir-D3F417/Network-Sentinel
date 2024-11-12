import os
import stat
import psutil
import logging
from pathlib import Path
from .validation import validate_interface

class SecurityChecker:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.secure_paths = {
            'models': Path('./models'),
            'logs': Path('./logs'),
            'config': Path('./config')
        }
        
    def check_root_privileges(self):
        """Check if running with necessary privileges"""
        try:
            if os.name == 'nt':  # Windows
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:  # Unix-like
                return os.geteuid() == 0
        except Exception as e:
            self.logger.error(f"Error checking privileges: {e}")
            return False

    def check_file_permissions(self):
        """Verify and fix file permissions"""
        try:
            for path_name, path in self.secure_paths.items():
                if not path.exists():
                    path.mkdir(mode=0o700, parents=True)
                else:
                    # Check and fix permissions
                    current_perms = stat.S_IMODE(os.stat(path).st_mode)
                    if current_perms != 0o700:
                        os.chmod(path, 0o700)
                        self.logger.warning(f"Fixed permissions for {path_name}")
            return True
        except Exception as e:
            self.logger.error(f"Error checking file permissions: {e}")
            return False

    def check_network_access(self, interface=None):
        """Verify network interface access"""
        try:
            if interface:
                validate_interface(interface)
                # Check if interface exists and is up
                addrs = psutil.net_if_addrs()
                if interface not in addrs:
                    raise ValueError(f"Interface {interface} not found")
            return True
        except Exception as e:
            self.logger.error(f"Network access check failed: {e}")
            return False

    def validate_ml_models(self):
        """Verify ML model integrity"""
        try:
            model_path = self.secure_paths['models']
            for model_file in model_path.glob('*.joblib'):
                # Check file hash against known good values
                if not self._verify_file_hash(model_file):
                    self.logger.error(f"Model file integrity check failed: {model_file}")
                    return False
            return True
        except Exception as e:
            self.logger.error(f"Error validating ML models: {e}")
            return False

    def _verify_file_hash(self, file_path):
        """Verify file integrity using SHA-256"""
        import hashlib
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
                # Compare with stored hash (implement hash storage mechanism)
                return True  # Placeholder
        except Exception as e:
            self.logger.error(f"Error verifying file hash: {e}")
            return False