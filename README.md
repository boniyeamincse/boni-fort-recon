# 🛡️ Boni Fort Recon

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub stars](https://img.shields.io/github/stars/boniyeamincse/boni-fort-recon.svg)](https://github.com/boniyeamincse/boni-fort-recon/stargazers)

## 📋 Project Structure
```
boni-fort-recon/
├── Auto-Recon/
│   ├── auto-recon.sh         # Main script
│   ├── config.conf          # Configuration file
│   ├── notify.sh           # Notification handler
│   └── tool_requirements.md # Tool dependencies
├── .github/
│   └── workflows/
│       └── ci.yml          # CI pipeline
└── README.md               # Documentation
```

## 🌟 Features
- Automated subdomain enumeration
- DNS resolution & HTTP service detection
- Port scanning with Naabu/Nmap integration
- Vulnerability assessment (Nikto & Nmap scripts)
- Parallel processing for fast execution
- Comprehensive reporting
- Multi-distro support (APT, YUM, DNF, Pacman, etc.)

## 📦 Installation

### Prerequisites
- Linux (Debian/Ubuntu/RHEL/Arch)
- Root privileges
- Internet connection

### Quick Install
```bash
git clone https://github.com/boniyeamincse/boni-fort-recon.git
cd boni-fort-recon
chmod +x Auto-Recon/auto-recon.sh
sudo ./Auto-Recon/auto-recon.sh --install-deps
```

### Package Manager Support
1. **APT (Debian/Ubuntu)**
```bash
sudo apt update && sudo apt install -y golang git python3 python3-pip nmap nikto libpcap-dev
```

2. **DNF (Fedora/RHEL 8+)**
```bash
sudo dnf install -y golang git python3 python3-pip nmap nikto libpcap-devel
```

3. **YUM (CentOS/RHEL 7)**
```bash
sudo yum install -y golang git python3 python3-pip nmap nikto libpcap-devel
```

4. **Pacman (Arch)**
```bash
sudo pacman -S --noconfirm go git python python-pip nmap nikto libpcap
```

## 🚀 Usage

### Basic Scan
```bash
sudo ./auto-recon.sh -d example.com
```

### Quick Scan
```bash
sudo ./auto-recon.sh -d example.com -q
```

### Full Scan
```bash
sudo ./auto-recon.sh -d example.com -f -n -v
```

### Custom Port Scan
```bash
sudo ./auto-recon.sh -d example.com -p "80,443,8080" -t 100
```

## ⚙️ Configuration

### Main Configuration (config.conf)
```ini
# Performance settings
MAX_THREADS=100
TIMEOUT=15
RATE_LIMIT_REQUESTS=200

# Port lists
QUICK_PORTS="80,443,8080,8443"
WEB_PORTS="80,443,8080,8443,3000,5000,8000"

# Tool settings
SUBFINDER_THREADS=100
AMASS_TIMEOUT=10
HTTPX_RATE=150
NAABU_RATE=1000
```

### Notifications (notify.sh)
```bash
# Configure webhooks
SLACK_WEBHOOK="your_slack_webhook"
DISCORD_WEBHOOK="your_discord_webhook"
```

## 📊 Output Structure
```
results/
├── target.com_20240318/
│   ├── subdomains/        # Subdomain results
│   ├── active/           # Active hosts
│   ├── scanning/        # Scan results
│   └── vulnerabilities/ # Security findings
```

## 🛠️ Command Line Options
```
Options:
  -d    Target domain
  -o    Output directory
  -p    Ports to scan
  -t    Number of threads
  -w    Timeout in seconds
  -v    Enable vulnerability scanning
  -n    Enable Nmap scanning
  -s    Nmap scan type
  -q    Quick scan mode
  -f    Full scan mode
  -h    Show help message
```

## 🔄 CI/CD Pipeline
The project includes GitHub Actions workflow:
```yaml
name: CI Pipeline
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - name: Set up Go
      uses: actions/setup-go@v4
    - name: Run tests
      run: ./auto-recon.sh -d example.com -q
```

## 🐛 Troubleshooting

### Common Issues
1. **Permission Denied**
```bash
sudo chmod +x auto-recon.sh
```

2. **Missing Dependencies**
```bash
sudo ./auto-recon.sh --install-deps
```

3. **Network Issues**
```bash
sudo ./auto-recon.sh -d example.com -w 60 -t 30
```

## 🤝 Contributing
1. Fork the repository
2. Create feature branch
3. Commit changes
4. Push to branch
5. Create Pull Request

## 📝 License
MIT License - See [LICENSE](LICENSE) for details

## 👤 Author
**Boni Yeamin**
- GitHub: [@boniyeamincse](https://github.com/boniyeamincse)

---
Made with ❤️ by Boni Yeamin
