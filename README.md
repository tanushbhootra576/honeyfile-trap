# 🍯 Honeyfile Trap - Terminal-Based Cybersecurity Intrusion Detection Tool

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.7+-green.svg)](https://python.org)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://github.com)

A sophisticated terminal-based cybersecurity tool that leverages **honeyfiles** (decoy files) to detect unauthorized access and potential intrusions. When attackers interact with these trap files, the system generates real-time alerts, logs detailed incident information, and can notify administrators—all through an intuitive command-line interface.

## 🎯 Key Features

### 📂 Honeyfile Generator
- **Realistic Decoy Files**: Generate convincing fake files like `passwords.txt`, `financial_report.pdf`, `admin_config.docx`
- **Multiple Categories**: Sensitive, financial, corporate, and personal document types
- **Authentic Content**: Files contain believable (but fake) data to lure attackers
- **Metadata Spoofing**: Realistic file timestamps and sizes

### 👁️ Real-Time File Monitoring
- **Cross-Platform Support**: Works on Windows, Linux, and macOS
- **Process Tracking**: Identifies which processes access honeyfiles
- **User Detection**: Captures username and system information
- **Network Monitoring**: Optional IP and connection tracking
- **Low Overhead**: Efficient monitoring with minimal system impact

### ⚠️ Intelligent Alert System
- **Real-Time Notifications**: Immediate terminal alerts when files are accessed
- **Severity Levels**: Critical, High, Medium, and Low priority alerts
- **Colorized Output**: Eye-catching terminal displays with emoji indicators
- **Email Integration**: Optional SMTP notifications to administrators
- **Sound Alerts**: Audio notifications for immediate attention

### 📜 Comprehensive Logging
- **Structured Logging**: JSON, CSV, or text format options
- **Rich Metadata**: Process IDs, usernames, timestamps, file paths
- **Log Rotation**: Automatic file rotation with configurable size limits
- **Export Capabilities**: Export logs for external analysis
- **Report Generation**: Summary reports with statistics and trends

### 🔐 Security Features
- **Log Encryption**: Optional AES or RSA encryption for log files
- **Integrity Verification**: Hash-based file integrity checking
- **Access Control**: Process-level access monitoring
- **Stealth Operation**: Minimal system footprint

## 🚀 Quick Start

### Installation

1. **Clone the repository**:
```bash
git clone https://github.com/yourusername/honeyfile-trap.git
cd honeyfile-trap
```

2. **Install dependencies**:
```bash
pip install -r requirements.txt
```

3. **Run interactive setup** (optional):
```bash
python honeyfile_trap.py config --setup
```

### Basic Usage

1. **Generate honeyfiles**:
```bash
python honeyfile_trap.py generate --count 15
```

2. **Start monitoring**:
```bash
python honeyfile_trap.py monitor
```

3. **View recent alerts**:
```bash
python honeyfile_trap.py logs --type alert --limit 20
```

4. **Generate security report**:
```bash
python honeyfile_trap.py report --days 7 --output security_report.json
```

## 📋 Detailed Usage

### Command Reference

#### Generate Honeyfiles
```bash
# Generate 10 random honeyfiles
python honeyfile_trap.py generate

# Generate 25 files from specific categories
python honeyfile_trap.py generate --count 25 --categories sensitive financial

# List existing honeyfiles
python honeyfile_trap.py list

# Clear all honeyfiles (with confirmation)
python honeyfile_trap.py clear
```

#### Monitoring Operations
```bash
# Start monitoring (press Ctrl+C to stop)
python honeyfile_trap.py monitor

# Use custom configuration file
python honeyfile_trap.py --config ./my_config.yaml monitor
```

#### Log Management
```bash
# View recent file access logs
python honeyfile_trap.py logs --type access --limit 50

# View alerts from last 3 days
python honeyfile_trap.py logs --type alert --days 3

# View system events
python honeyfile_trap.py logs --type system

# Export logs to CSV
python honeyfile_trap.py export --type access --format csv --output access_logs.csv
```

#### Reports and Analytics
```bash
# Generate 30-day summary report
python honeyfile_trap.py report --days 30

# Save report to file
python honeyfile_trap.py report --days 7 --output weekly_report.json
```

#### Configuration Management
```bash
# Interactive configuration setup
python honeyfile_trap.py config --setup

# Show current configuration
python honeyfile_trap.py config --show

# Validate configuration file
python honeyfile_trap.py config --validate

# Reset to default settings
python honeyfile_trap.py config --reset
```

## ⚙️ Configuration

The system uses a YAML configuration file located at `./config/config.yaml`. Here's a sample configuration:

```yaml
monitoring:
  enabled: true
  check_interval: 1.0
  recursive: true

honeyfiles:
  directory: "./honeyfiles"
  types: ["txt", "doc", "docx", "pdf", "xls", "xlsx", "zip"]

alerts:
  enabled: true
  sound: false
  terminal_color: true
  log_level: "INFO"

logging:
  enabled: true
  directory: "./logs"
  max_file_size: "10MB"
  backup_count: 5
  encryption: false
  format: "json"

security:
  collect_process_info: true
  collect_user_info: true
  collect_network_info: false

notifications:
  email:
    enabled: false
    smtp_server: "smtp.gmail.com"
    smtp_port: 587
    username: "your-email@gmail.com"
    password: "your-app-password"
    recipients: ["admin@company.com"]
```

### Configuration Options

| Section | Option | Description | Default |
|---------|--------|-------------|---------|
| `monitoring` | `enabled` | Enable file monitoring | `true` |
| | `check_interval` | Monitoring frequency (seconds) | `1.0` |
| | `recursive` | Monitor subdirectories | `true` |
| `honeyfiles` | `directory` | Honeyfile storage location | `"./honeyfiles"` |
| | `types` | File extensions to generate | `["txt", "doc", ...]` |
| `alerts` | `terminal_color` | Colored terminal output | `true` |
| | `sound` | Audio notifications | `false` |
| | `log_level` | Alert verbosity level | `"INFO"` |
| `logging` | `max_file_size` | Log rotation size | `"10MB"` |
| | `encryption` | Encrypt log files | `false` |
| | `format` | Log format (json/csv/text) | `"json"` |
| `security` | `collect_process_info` | Track accessing processes | `true` |
| | `collect_user_info` | Collect user information | `true` |
| | `collect_network_info` | Monitor network connections | `false` |

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Honeyfile Trap System                    │
├─────────────────────────────────────────────────────────────┤
│  🍯 Honeyfile Generator  │  👁️  File Monitor               │
│  • Generate decoy files   │  • Cross-platform monitoring    │
│  • Realistic content      │  • Process tracking             │
│  • Multiple categories    │  • Event detection              │
├─────────────────────────────────────────────────────────────┤
│  ⚠️  Alert System        │  📜 Incident Logger             │
│  • Real-time alerts      │  • Structured logging           │
│  • Email notifications   │  • Log encryption               │
│  • Severity levels       │  • Report generation            │
├─────────────────────────────────────────────────────────────┤
│  ⚙️  Configuration       │  🔐 Security Features          │
│  • YAML-based config     │  • Optional encryption          │
│  • Interactive setup     │  • Integrity verification       │
│  • Validation system     │  • Access control              │
└─────────────────────────────────────────────────────────────┘
```

## 🔧 Technical Details

### Requirements
- **Python**: 3.7 or higher
- **Operating System**: Windows, Linux, macOS
- **Memory**: Minimal (< 50MB typical usage)
- **Storage**: Configurable log rotation
- **Permissions**: Read/write access to honeyfile and log directories

### Dependencies
- `watchdog`: Cross-platform file system monitoring
- `cryptography`: Encryption and security features
- `psutil`: System and process information
- `colorama`: Cross-platform terminal colors
- `pyyaml`: Configuration file parsing

### File Monitoring Technology
The system uses the `watchdog` library for efficient, cross-platform file system monitoring:
- **Windows**: ReadDirectoryChangesW API
- **Linux**: inotify system
- **macOS**: FSEvents API

This approach provides real-time file access detection with minimal CPU overhead.

## 📊 Sample Output

### Terminal Monitoring Display
```
🍯 HONEYFILE TRAP - INTRUSION DETECTION SYSTEM
═══════════════════════════════════════════════
Status: ACTIVE
Time: 2024-03-15 14:30:22
Press Ctrl+C to stop monitoring

🔍 File Monitor initialized
   Directory: D:\honeyfiles
   Check interval: 1.0s

📋 Found 12 honeyfiles to monitor:
   • admin_access.txt
   • budget_2024.xlsx
   • confidential_memo.docx
   • database_config.txt
   • passwords.txt
   ...

✅ File monitor started successfully
   Monitoring 12 honeyfiles

═══════════════════════════════════════════════
🚨 HONEYFILE ACCESSED!
📁 File: passwords.txt
🔧 Action: opened
⏰ 2024-03-15 14:32:45
⚙️  Possible processes:
   • PID 2847: notepad.exe (john_user)
   • PID 1234: explorer.exe (john_user)
👤 User: john_user on Windows
═══════════════════════════════════════════════
```

### Log Entry Example (JSON format)
```json
{
  "event_type": "file_access",
  "timestamp": "2024-03-15T14:32:45.123456",
  "file_path": "./honeyfiles/passwords.txt",
  "file_name": "passwords.txt",
  "access_type": "opened",
  "severity": "CRITICAL",
  "process_info": {
    "possible_accessing_processes": [
      {
        "pid": 2847,
        "name": "notepad.exe",
        "username": "john_user",
        "cmdline": "notepad.exe ./honeyfiles/passwords.txt"
      }
    ]
  },
  "user_info": {
    "username": "john_user",
    "platform": "Windows",
    "hostname": "DESKTOP-ABC123"
  },
  "hash": "a1b2c3d4e5f6789a"
}
```

### Summary Report Example
```
📈 SUMMARY REPORT (7 days)
══════════════════════════════════════════════
File accesses: 23
Alerts generated: 18
Unique files accessed: 8

Most accessed files:
   • passwords.txt (7 times)
   • admin_config.txt (4 times)
   • financial_report.pdf (3 times)

Alert levels:
   • CRITICAL: 7
   • HIGH: 4
   • MEDIUM: 7
```

## 🛡️ Security Considerations

### Best Practices
1. **File Placement**: Place honeyfiles in locations where legitimate users shouldn't access them
2. **Realistic Names**: Use convincing filenames that would attract attackers
3. **Access Monitoring**: Regularly review access logs for patterns
4. **Network Segmentation**: Deploy in network segments with sensitive data
5. **Log Security**: Enable encryption for log files in sensitive environments

### Limitations
- **False Positives**: Legitimate system processes may trigger alerts
- **Platform Differences**: Some features may vary between operating systems
- **Performance**: High-frequency file access may generate many alerts
- **Detection Evasion**: Sophisticated attackers may detect honeyfiles

## 🤝 Contributing

We welcome contributions! Here's how to get started:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature-name`
3. **Make your changes** with proper documentation
4. **Add tests** for new functionality
5. **Submit a pull request** with a clear description

### Development Setup
```bash
# Clone your fork
git clone https://github.com/yourusername/honeyfile-trap.git
cd honeyfile-trap

# Install development dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Run with verbose output for debugging
python honeyfile_trap.py --verbose monitor
```

## 📈 Roadmap

### Planned Features
- [ ] **Web Dashboard**: Browser-based monitoring interface
- [ ] **Database Integration**: PostgreSQL/MySQL log storage
- [ ] **Machine Learning**: Anomaly detection and behavior analysis
- [ ] **Distributed Deployment**: Multi-system coordination
- [ ] **Custom Alerting**: Slack, Discord, Teams integrations
- [ ] **Advanced Decoys**: Binary file generation, registry honeykeys
- [ ] **Threat Intelligence**: IOC integration and threat feeds

### Version History
- **v1.0.0**: Initial release with core functionality
- **v0.9.0**: Beta release with basic monitoring
- **v0.5.0**: Alpha release with honeyfile generation

## 🐛 Troubleshooting

### Common Issues

**Q: Monitoring doesn't start**
A: Check that the honeyfiles directory exists and contains files. Run `python honeyfile_trap.py list` to verify.

**Q: No alerts when files are accessed**
A: Ensure you're accessing files as a different user/process. Some systems may not detect self-access.

**Q: Email notifications not working**
A: Verify SMTP settings and use app-specific passwords for Gmail. Check firewall settings.

**Q: High CPU usage**
A: Increase the `check_interval` in configuration or reduce the number of monitored files.

**Q: Permission errors**
A: Ensure the application has read/write access to log directories and honeyfile locations.

### Debug Mode
```bash
# Enable verbose output for troubleshooting
python honeyfile_trap.py --verbose monitor

# Validate configuration
python honeyfile_trap.py config --validate

# Test honeyfile generation
python honeyfile_trap.py generate --count 1
python honeyfile_trap.py list
```

### Log Analysis
```bash
# Check system logs for startup issues
python honeyfile_trap.py logs --type system --limit 50

# Review recent file access patterns
python honeyfile_trap.py logs --type access --days 1

# Export logs for external analysis
python honeyfile_trap.py export --format csv --output debug_logs.csv
```

## 📞 Support

- **Documentation**: Check this README and inline code documentation
- **Issues**: Report bugs on [GitHub Issues](https://github.com/yourusername/honeyfile-trap/issues)
- **Discussions**: Join conversations in [GitHub Discussions](https://github.com/yourusername/honeyfile-trap/discussions)
- **Security**: Report security issues privately to security@yourproject.com

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Watchdog Library**: Cross-platform file system monitoring
- **Cryptography Project**: Security and encryption capabilities
- **PSUtil**: System and process information utilities
- **Colorama**: Cross-platform terminal color support
- **Community**: Thanks to all contributors and security researchers

---

**⚠️ Disclaimer**: This tool is designed for legitimate cybersecurity defense and monitoring purposes. Users are responsible for ensuring compliance with applicable laws and organizational policies. The authors are not responsible for misuse or damages resulting from the use of this software.

**🛡️ Security Notice**: Always test in a controlled environment before deployment. Regularly review and audit monitoring configurations and access patterns.