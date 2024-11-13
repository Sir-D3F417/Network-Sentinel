# Network Sentinel

![Version](https://img.shields.io/badge/version-2.0.0--beta-blue)
![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
[![codecov](https://codecov.io/gh/Sir-D3F417/Network-Sentinel/branch/main/graph/badge.svg)](https://codecov.io/gh/Sir-D3F417/Network-Sentinel)

![Alt Text](https://s8.uupload.ir/files/leonardo_phoenix_a_sleek_and_futuristic_3d_banner_for_network_1_jjeq.jpg)

<img src="https://s8.uupload.ir/files/leonardo_phoenix_a_sleek_and_futuristic_3d_banner_for_network_1_jjeq.jpg" alt="Alt Text" style="width:100%;">

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

## Install system dependencies (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install python3-dev python3-pip tcpdump wireshark
```
- Clone repository
```bash
git clone https://github.com/D3F417/network-sentinel.git
cd network-sentinel
```
- Create virtual environment
```bash
python3 -m venv venv
source venv/bin/activate
```
- Install requirements

```bash
pip install -r requirements.txt
```
- Install package

```bash
pip install -e .
```

- Check if installed

```bash
pip list | grep network-sentinel
```

- Test CLI

```bash
network-sentinel --help
```

- List available interfaces

```bash
sudo network-sentinel list-interfaces
```

- Start monitoring (replace eth0 with your interface)

```bash
sudo network-sentinel monitor -i eth0 -v
```

## Windows

- Install Npcap from https://npcap.com/#download

- Open PowerShell as Administrator and run:

```bash
Set-ExecutionPolicy RemoteSigned
```

- Create virtual environment

```bash
python -m venv venv
```

- Activate (PowerShell)

```bash
.\venv\Scripts\Activate.ps1
Or CMD
venv\Scripts\activate.bat
```

-Install requirements

```bash
pip install -r requirements.txt
```

- Install the package in development mode

```bash
pip install -e .
```

- Check if installed

```bash
pip list | findstr network-sentinel
```

- Test CLI

```bash
network-sentinel --help
```


Open PowerShell as Administrator and run:
List available interfaces

```bash
network-sentinel list-interfaces
```
- Start monitoring (replace "Wi-Fi" with your interface name)

```bash
network-sentinel monitor -i "Wi-Fi" -v
```

## Usage

List available interfaces
```bash
sudo network-sentinel list-interfaces
```
Start monitoring (replace eth0 with your interface)
```bash
sudo network-sentinel monitor -i eth0 -v
```
## Beta Notice
This is a beta release. While the tool is functional, you may encounter bugs or incomplete features. Please report any issues on GitHub.

## License

[MIT](https://choosealicense.com/licenses/mit/)

## Credits
Created by D3F417 (RastaKhiz Team)
