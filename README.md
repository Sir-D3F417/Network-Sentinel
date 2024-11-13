# Network Sentinel

![Version](https://img.shields.io/badge/version-2.0.0--beta-blue)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue)](https://www.python.org/downloads/)
[![CodeCov](https://codecov.io/gh/Sir-D3F417/Network-Sentinel/branch/main/graph/badge.svg)](https://codecov.io/gh/Sir-D3F417/Network-Sentinel)
[![Telegram](https://img.shields.io/badge/Join%20Us-Telegram-blue?style=flat&logo=telegram)](https://t.me/RastakhizTM)
[![Stars](https://img.shields.io/github/stars/Sir-D3F417/Network-Sentinel?style=social)](https://github.com/Sir-D3F417/Network-Sentinel/stargazers)

![Alt Text](https://s8.uupload.ir/files/leonardo_phoenix_a_sleek_and_futuristic_3d_banner_for_network_1_jjeq.jpg)

## Advanced Network Security Monitoring Tool

Network Sentinel is a sophisticated network security monitoring tool that uses machine learning for threat detection and real-time network analysis.

### Key Features
- 🔍 Real-time packet analysis and threat detection
- 🤖 Machine Learning-based anomaly detection
- 🚨 Advanced port scan detection (NULL, SYN, ACK scans)
- 📊 Live traffic monitoring and visualization
- 🛡️ Detection of common attack patterns
- 📝 Detailed logging and reporting
- 🔐 Secure storage of sensitive data
- 📈 Performance monitoring and optimization

### Security Features
- SYN/ACK flood detection
- Port scan detection
- Malware C2 channel detection
- Suspicious connection monitoring
- Known threat detection
- Custom rule support

## 🐛 Reporting Issues

### Bug Reports
1. Go to [Issues](https://github.com/Sir-D3F417/Network-Sentinel/issues)
2. Click "New Issue"
3. Select "🐛 Bug Report"
4. Fill in the template with detailed information
5. Include logs and screenshots if possible

### Feature Requests
1. Go to [Issues](https://github.com/Sir-D3F417/Network-Sentinel/issues)
2. Click "New Issue"
3. Select "💡 Feature Request"
4. Describe your feature idea
5. Explain the use case and benefits

   
## Created By
- **Author**: D3F417
- **Team**: RastaKhiz Team
- **Version**: 2.0.0-beta

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
