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
    if os.name == 'nt':  # Windows
        # Allow Unicode characters for Windows interface names
        if not re.match(r'^[a-zA-Z0-9_\- \u0080-\uffff]+$', interface):
            raise ValueError("Invalid interface name")
    else:  # Unix-like
        if not re.match(r'^[a-zA-Z0-9_-]+$', interface):
            raise ValueError("Invalid interface name")
    return interface

def sanitize_filename(filename):
    """Sanitize file names to prevent path traversal"""
    return os.path.basename(filename) 
