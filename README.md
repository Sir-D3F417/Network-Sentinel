# Network Sentinel

![Version](https://img.shields.io/badge/version-2.1.0---blue)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue)](https://www.python.org/downloads/)
[![CodeCov](https://codecov.io/gh/Sir-D3F417/Network-Sentinel/branch/main/graph/badge.svg)](https://codecov.io/gh/Sir-D3F417/Network-Sentinel)
[![Telegram](https://img.shields.io/badge/Join%20Us-Telegram-blue?style=flat&logo=telegram)](https://t.me/RastakhizTM)
[![Stars](https://img.shields.io/github/stars/Sir-D3F417/Network-Sentinel?style=social)](https://github.com/Sir-D3F417/Network-Sentinel/stargazers)

![Alt Text](https://s8.uupload.ir/files/leonardo_phoenix_a_sleek_and_futuristic_3d_banner_for_network_1_jjeq.jpg)

## 🌈 Advanced Network Security Monitoring Tool

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
- Machine Learning Integration
- Anomaly detection using Isolation Forest
- Pattern recognition for attack detection
- Adaptive threat detection with continuous learning
- Real-time classification of threats
### Real-time Monitoring
- Live packet analysis and inspection
- Traffic visualization and statistics
- Resource usage monitoring
- Performance optimization
- Automated alerts

### Security Features
- Advanced scan detection
- Flood attack prevention
- Malware C2 detection
- Secure data storage
- Privilege management
- Encrypted storage of sensitive data

### Security Features
- SYN/ACK flood detection
- Port scan detection
- Malware C2 channel detection
- Suspicious connection monitoring
- Known threat detection
- Custom rule support

## 👾 Technical Specifications

- Python 3.8+ compatibility
- Cross-platform support (Windows, Linux)
- Modular architecture
- Extensible plugin system
- REST API support (upcoming)
- ML-powered threat detection


### Known Issues

- High CPU usage during initial ML training
- False positives in certain network conditions
- Limited IPv6 support
- Memory optimization needed for large networks

### Upcoming Features

- Enhanced ML model accuracy
- GUI interface
- Network topology mapping
- Threat intelligence integration
- Advanced reporting system
- Cloud integration

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
- **Version**: 2.1.0

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

![](https://s8.uupload.ir/files/record_2024_11_16_05_41_32_141_0z5l.gif)

## Windows

### Windows Prerequisites

1. Install Npcap:
   - Download from [Npcap website](https://npcap.com/#download)
   - Run installer as administrator
   - Select "Install Npcap in WinPcap API-compatible Mode"

2. Install Wireshark (optional but recommended):
   - Download from [Wireshark website](https://www.wireshark.org/download.html)
   - This will provide the manufacturer database for better device identification

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

![](https://s8.uupload.ir/files/record_2024_11_16_05_40_40_751_iei0.gif)

## Authors

- **D3F417** - *Initial work and maintenance* - [Sir-D3F417](https://github.com/Sir-D3F417)
- **RastaKhiz Team** - *Development Team*

## Contact

- Email: info@d3f417.info
- GitHub: [Sir-D3F417](https://github.com/Sir-D3F417)


## License

[MIT](https://choosealicense.com/licenses/mit/)

## Uninstall on Windows

Stop the service if installed
```bash
Stop-Service NetworkSentinel -ErrorAction SilentlyContinue
```
```bash
pip uninstall network-sentinel -y
```
Remove configuration and data directories
```bash
Remove-Item -Path "$env:APPDATA\Network-Sentinel" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:LOCALAPPDATA\Network-Sentinel" -Recurse -Force -ErrorAction SilentlyContinue
```

Remove logs
```bash
Remove-Item -Path ".\logs" -Recurse -Force -ErrorAction SilentlyContinue
```
Remove models
```bash
Remove-Item -Path ".\models" -Recurse -Force -ErrorAction SilentlyContinue
```
Remove session data
```bash
Remove-Item -Path "session_stats.json" -Force -ErrorAction SilentlyContinue
Remove-Item -Path ".enc" -Force -ErrorAction SilentlyContinu
```
