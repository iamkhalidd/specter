# Specter

> **Cross-Platform Cybersecurity Forensic Toolkit**

A powerful CLI tool for security professionals to accelerate forensic investigations.

## Quick Start

```bash
# Interactive menu mode
python specter.py

# Or with CLI commands
python -m forensic_tool.main --help
```

## Features

| Category | Capabilities |
|----------|--------------|
| 📁 **File Forensics** | MD5/SHA256 hashing, Entropy analysis, YARA scanning |
| 📊 **Log Analysis** | SQLi, XSS, LFI detection, Brute force detection |
| 🌐 **Network** | Live connections, PCAP analysis |
| 🎯 **Threat Intel** | VirusTotal, AbuseIPDB, IOC scanning |
| 🔧 **System** | Autoruns, Process analysis, Timeline builder |
| 📋 **Reports** | Professional HTML/JSON reports |

## Installation

```bash
pip install -r requirements.txt

# Optional: Install as command
pip install -e .
specter  # Run interactive mode
```

## Commands

### Interactive Mode
```bash
python specter.py
```
Launches a numbered menu for easy navigation through all features.

### CLI Mode
```bash
# File forensics
python -m forensic_tool.main hash /path/to/file
python -m forensic_tool.main entropy /path/to/file
python -m forensic_tool.main yara /path/to/scan

# Log analysis
python -m forensic_tool.main logs /var/log/access.log --attacks --brute

# Network
python -m forensic_tool.main connections --suspicious
python -m forensic_tool.main pcap capture.pcap

# Threat intel
python -m forensic_tool.main check-hash /path/to/file --vt
python -m forensic_tool.main check-ip 192.168.1.1 --abuse
python -m forensic_tool.main ioc-scan /path/to/dir

# System
python -m forensic_tool.main autoruns
python -m forensic_tool.main processes
python -m forensic_tool.main timeline /path/to/dir

# Reports
python -m forensic_tool.main report full --output my_report
```

## Configuration

Create a config file:
```bash
python -m forensic_tool.main init-config
```

Set API keys in `~/.forensic.yaml` or environment variables:
- `VIRUSTOTAL_API_KEY`
- `ABUSEIPDB_API_KEY`

## Author

**Khalid** - [GitHub](https://github.com/khalid/specter)

## License

MIT License
