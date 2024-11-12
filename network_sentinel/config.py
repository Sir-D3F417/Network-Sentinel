from dataclasses import dataclass
import yaml
import os

@dataclass
class NetworkSentinelConfig:
    # Thresholds
    syn_flood_threshold: int = 100
    udp_flood_threshold: int = 1000
    icmp_flood_threshold: int = 50
    port_scan_window: int = 60
    
    # ML Configuration
    anomaly_contamination: float = 0.1
    classifier_estimators: int = 100
    training_interval: int = 3600
    
    # Alert Settings
    alert_cooldown: int = 5
    alert_buffer_size: int = 10
    
    # Logging
    log_level: str = "INFO"
    log_file: str = "network_sentinel.log"
    
    @classmethod
    def load(cls, config_path="config.yaml"):
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config_dict = yaml.safe_load(f)
                return cls(**config_dict)
        return cls() 