import ipaddress
import re
import os

def validate_ip(ip_str):
    try:
        return str(ipaddress.ip_address(ip_str))
    except ValueError:
        return None

def validate_interface(interface):
    """Validate network interface name"""
    if not re.match(r'^[a-zA-Z0-9_-]+$', interface):
        raise ValueError("Invalid interface name")
    return interface

def sanitize_filename(filename):
    """Sanitize file names to prevent path traversal"""
    return os.path.basename(filename) 