# 🛡️ Boni Fort Recon

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub stars](https://img.shields.io/github/stars/boniyeamincse/boni-fort-recon.svg)](https://github.com/boniyeamincse/boni-fort-recon/stargazers)

![Banner](https://i.ibb.co/m0b6W2H/security-scan-footer.png)

## 📌 Table of Contents
- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Configuration](#-configuration)
- [Advanced Usage](#-advanced-usage)
- [Contributing](#-contributing)
- [License](#-license)

## 🌟 Features
- Automated subdomain enumeration
- DNS resolution & HTTP service detection
- Port scanning with Naabu/Nmap integration
- Vulnerability assessment (Nikto & Nmap scripts)
- Parallel processing for fast execution
- Comprehensive reporting (HTML/Text/Markdown)
- Resume capability for interrupted scans

## 📦 Installation

### System Requirements
- OS: Linux (Debian/Ubuntu recommended)
- RAM: 4GB+ (8GB recommended)
- Storage: 20GB+ free space
- Network: Stable internet connection

### Step-by-Step Installation

1. **Clone Repository**
```bash
git clone https://github.com/boniyeamincse/boni-fort-recon.git
cd boni-fort-recon
```

2. **Install Dependencies**
```bash
pip install -r requirements.txt
```


For Debian/Ubuntu
sudo apt update && sudo apt install -y \
golang git python3 python3-pip \
nmap nikto libpcap-dev
bash
echo 'export GOPATH=$HOME/go' >> ~/.bashrc
echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
source ~/.bashrc
bash
chmod +x auto-recon.sh
sudo ./auto-recon.sh --install-deps
bash
./auto-recon.sh --version
bash
Quick scan (fast results)
sudo ./auto-recon.sh -d example.com -q
Full scan (comprehensive analysis)
sudo ./auto-recon.sh -d example.com -f -v -n
bash
./auto-recon.sh -d target.com -o initial_scan -q
bash
./auto-recon.sh -d webapp.com -p "80,443,8080" -v -t 100
bash
./auto-recon.sh -d company.com -f -n -p "1-65535" -w 60
ini
[performance]
threads = 100
timeout = 15
[scanning]
quick_ports = 80,443,8080,8443
full_ports = 1-65535
[notifications]
slack_webhook = "YOUR_SLACK_WEBHOOK"
discord_webhook = "YOUR_DISCORD_WEBHOOK"
results/
├── target.com_20240318_120130/
│ ├── subdomains/ # Raw subdomain data
│ ├── active/ # Verified targets
│ ├── scans/ # Scan results
│ ├── report.html # HTML summary
│ └── timeline.log # Execution log
bash
sudo chown -R $USER:$USER /path/to/results
bash
sudo ./auto-recon.sh --install-deps
bash
Reduce threads and increase timeout
./auto-recon.sh -d target.com -t 30 -w 60
This README includes:
1. Comprehensive installation instructions
Detailed user guide with examples
3. Configuration reference
Troubleshooting section
Clear output structure visualization
Contribution guidelines
License information
Responsive badges and banners
Would you like me to add any specific use cases or configuration examples?
