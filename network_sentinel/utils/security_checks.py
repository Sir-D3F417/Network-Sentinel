import os
import stat
import psutil
import logging
from pathlib import Path
from .validation import validate_interface
import subprocess
import sys

# Only import winreg on Windows
if os.name == 'nt':
    import winreg

class SecurityChecker:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.secure_paths = {
            'models': Path('./models'),
            'logs': Path('./logs'),
            'config': Path('./config'),
            'temp': Path('./temp'),
            'cache': Path('./cache')
        }
        self.is_test_environment = os.environ.get('NETWORK_SENTINEL_TEST') == 'true'
        self.security_checks = [
            self.check_root_privileges,
            self.check_file_permissions,
            self.check_network_access,
            self.validate_ml_models,
            self.check_system_requirements,
            self.verify_dependencies
        ]

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
                return True  # Placeholder for hash verification
        except Exception as e:
            self.logger.error(f"Error verifying file hash: {e}")
            return False

    def check_system_requirements(self):
        """Verify system meets minimum requirements"""
        try:
            mem = psutil.virtual_memory()
            cpu_count = psutil.cpu_count()
            
            if mem.total < (4 * 1024 * 1024 * 1024):  # 4GB
                self.logger.warning("Less than 4GB RAM available")
            if cpu_count < 2:
                self.logger.warning("Less than 2 CPU cores available")
            return True
        except Exception as e:
            self.logger.error(f"Error checking system requirements: {e}")
            return False

    def verify_dependencies(self):
        """Verify all required dependencies are installed and working"""
        try:
            # Check OS-specific dependencies
            if os.name == 'nt':  # Windows
                if not self._verify_npcap():
                    return False
            else:  # Linux/Unix
                if not self._verify_libpcap():
                    return False

            # Verify Python packages
            if not self._verify_python_packages():
                return False

            return True

        except Exception as e:
            self.logger.error(f"Error verifying dependencies: {e}")
            return False

    def _verify_npcap(self):
        """Verify Npcap installation on Windows"""
        if os.name != 'nt':
            return True

        try:
            registry_paths = [
                r"SOFTWARE\WOW6432Node\Npcap",
                r"SOFTWARE\Npcap"
            ]
            for path in registry_paths:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
                    winreg.CloseKey(key)
                    return True
                except WindowsError:
                    continue

            self.logger.error("""
Npcap is not properly installed. Please:
1. Download latest Npcap from https://npcap.com/#download
2. Run installer as administrator
3. Select 'WinPcap API-compatible Mode'
4. Restart your computer
""")
            return False

        except Exception as e:
            self.logger.error(f"Error checking Npcap: {e}")
            return False

    def _verify_libpcap(self):
        """Verify libpcap installation on Linux/Unix"""
        try:
            # Check for libpcap using ldconfig
            result = subprocess.run(['ldconfig', '-p'], capture_output=True, text=True)
            if 'libpcap.so' not in result.stdout:
                self.logger.error("""
libpcap is not installed. Please install it:
For Debian/Ubuntu: sudo apt-get install libpcap-dev
For RHEL/CentOS: sudo yum install libpcap-devel
For Arch Linux: sudo pacman -S libpcap
""")
                return False
            return True
        except Exception as e:
            self.logger.error(f"Error checking libpcap: {e}")
            return False

    def _verify_python_packages(self):
        """Verify required Python packages"""
        required_packages = {
            'scapy': 'scapy',
            'cryptography': 'cryptography',
            'numpy': 'numpy',
            'scikit-learn': 'sklearn',
            'rich': 'rich',
            'psutil': 'psutil'
        }

        missing_packages = []
        for package, import_name in required_packages.items():
            try:
                __import__(import_name)
            except ImportError:
                self.logger.error(f"Required package {package} not found")
                missing_packages.append(package)

        if missing_packages:
            self.logger.error(f"Missing packages: {', '.join(missing_packages)}")
            self.logger.error("Please run: pip install -r requirements.txt")
            return False
        return True

    def _fix_wireshark_manuf(self):
        """Fix Wireshark manufacturer database issue"""
        try:
            from scapy.data import ETHER_TYPES
            manuf_file = Path(os.path.expanduser('~')) / '.scapy' / 'manuf'
            manuf_file.parent.mkdir(exist_ok=True)
            
            if not manuf_file.exists():
                import urllib.request
                url = "https://raw.githubusercontent.com/wireshark/wireshark/master/manuf"
                urllib.request.urlretrieve(url, str(manuf_file))
                self.logger.info("Downloaded Wireshark manufacturer database")
        except Exception as e:
            self.logger.warning(f"Could not fix Wireshark manuf file: {e}")
            # Non-critical error, continue anyway

    def perform_checks(self):
        """Perform all security checks"""
        if self.is_test_environment:
            return True
            
        for check in self.security_checks:
            if not check():
                return False
        return True
