import yaml
from pathlib import Path

class NetworkSentinelConfig:
    def __init__(self):
        # Default values
        self.syn_flood_threshold = 100
        self.udp_flood_threshold = 1000
        self.icmp_flood_threshold = 50
        self.port_scan_window = 60
        self.log_level = "INFO"
        self.log_file = "network_sentinel.log"
        self.alert_cooldown = 5
        self.alert_buffer_size = 10
        self.training_interval = 3600

    @classmethod
    def load(cls, config_file=None):
        config = cls()
        if config_file and Path(config_file).exists():
            with open(config_file, 'r') as f:
                data = yaml.safe_load(f)
                for key, value in data.items():
                    if hasattr(config, key):
                        setattr(config, key, value)
        return config 
