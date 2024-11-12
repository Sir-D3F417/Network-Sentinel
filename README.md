# Network Sentinel

![Version](https://img.shields.io/badge/version-2.0.0--beta-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Author](https://img.shields.io/badge/author-D3F417-orange)
![Team](https://img.shields.io/badge/team-RastaKhiz-red)

## About
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

</ul><p><code>sudo apt-get update</code></p>

</ul><p><code>sudo apt-get install python3-dev python3-pip tcpdump wireshark</code></p>

- Clone repository

</ul><p><code>git clone https://github.com/D3F417/network-sentinel.git</code></p>

</ul><p><code>cd network-sentinel</code></p>

- Create virtual environment

</ul><p><code>python3 -m venv venv</code></p>

</ul><p><code>source venv/bin/activate</code></p>

- Install requirements & ns tool

</ul><p><code>pip install -r requirements.txt</code></p>

</ul><p><code>pip install -e .</code></p>


- Check if installed

</ul><p><code>pip list | grep network-sentinel</code></p>

- Test CLI

</ul><p><code>network-sentinel --help</code></p>

- List available interfaces

</ul><p><code>sudo network-sentinel list-interfaces</code></p>

- Start monitoring (replace eth0 with your interface)

</ul><p><code>sudo network-sentinel monitor -i eth0 -v</code></p>

### Windows

- Install Npcap from https://npcap.com/#download

- Open PowerShell as Administrator and run:

</ul><p><code>Set-ExecutionPolicy RemoteSigned</code></p>

- Create virtual environment

</ul><p><code>python -m venv venv</code></p>

- Activate (PowerShell)

</ul><p><code>.\venv\Scripts\Activate.ps1</code></p>

- Or CMD

</ul><p><code>venv\Scripts\activate.bat</code></p>

- Install requirements

</ul><p><code>pip install -r requirements.txt</code></p>

- Install the package in development mode

</ul><p><code>pip install -e .</code></p>

- Check if installed

</ul><p><code>pip list | findstr network-sentinel</code></p>

- Test CLI

</ul><p><code>network-sentinel --help</code></p>

- Open PowerShell as Administrator and run:

- List available interfaces

</ul><p><code>network-sentinel list-interfaces</code></p>

- Start monitoring (replace "Wi-Fi" with your interface name)

</ul><p><code>network-sentinel monitor -i "Wi-Fi" -v</code></p>

## Usage

- List available interfaces

</ul><p><code>sudo network-sentinel list-interfaces</code></p>

- Start monitoring (replace eth0 with your interface)

</ul><p><code>sudo network-sentinel monitor -i eth0 -v</code></p>

## Beta Notice
This is a beta release. While the tool is functional, you may encounter bugs or incomplete features. Please report any issues on GitHub.

## License
MIT License - see LICENSE file for details.

## Credits
Created by D3F417 (RastaKhiz Team)
