# Network Sentinel

![Version](https://img.shields.io/badge/version-2.0.0--beta-blue)
![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Advanced Network Security Monitoring Tool with Machine Learning capabilities.

## Created By
- **Author**: D3F417
- **Team**: RastaKhiz Team
- **Version**: 2.0.0-beta

## Features
- Real-time network packet analysis
- Machine learning-based anomaly detection
- Multiple attack pattern recognition:
  - Port scanning (SYN, ACK, NULL, FIN, XMAS scans)
  - DDoS attacks (SYN flood, UDP flood, ICMP flood)
  - DNS amplification attacks
  - Suspicious connection detection
- Beautiful console interface with live statistics
- Automatic model training and adaptation

## Installation

### Linux

## Install system dependencies (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install python3-dev python3-pip tcpdump wireshark
## Clone repository
git clone https://github.com/D3F417/network-sentinel.git
cd network-sentinel
##Create virtual environment
python3 -m venv venv
source venv/bin/activate
Install requirements
pip install -r requirements.txt
Install package
pip install -e .

# Check if installed
pip list | grep network-sentinel

# Test CLI
network-sentinel --help

# List available interfaces
sudo network-sentinel list-interfaces

# Start monitoring (replace eth0 with your interface)
sudo network-sentinel monitor -i eth0 -v

### Windows
# Install Npcap from https://npcap.com/#download

# Open PowerShell as Administrator and run:
Set-ExecutionPolicy RemoteSigned

# Create virtual environment
python -m venv venv

# Activate (PowerShell)
.\venv\Scripts\Activate.ps1

# Or CMD
venv\Scripts\activate.bat

# Install requirements
pip install -r requirements.txt

# Install the package in development mode
pip install -e .

# Check if installed
pip list | findstr network-sentinel

# Test CLI
network-sentinel --help

# Open PowerShell as Administrator and run:
# List available interfaces
network-sentinel list-interfaces

# Start monitoring (replace "Wi-Fi" with your interface name)
network-sentinel monitor -i "Wi-Fi" -v

## Usage

List available interfaces
sudo network-sentinel list-interfaces
Start monitoring (replace eth0 with your interface)
sudo network-sentinel monitor -i eth0 -v

## Beta Notice
This is a beta release. While the tool is functional, you may encounter bugs or incomplete features. Please report any issues on GitHub.

## License
MIT License - see LICENSE file for details.

## Credits
Created by D3F417 (RastaKhiz Team)
