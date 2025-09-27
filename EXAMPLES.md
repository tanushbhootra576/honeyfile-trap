# 🧪 Honeyfile Trap - Example Usage and Testing

This document provides comprehensive examples and testing scenarios for the Honeyfile Trap system.

## 🚀 Quick Start Examples

### Example 1: Basic Setup and Monitoring

```bash
# Step 1: Navigate to the project directory
cd honeyfile-trap

# Step 2: Generate some initial honeyfiles
python honeyfile_trap.py generate --count 10

# Step 3: View the generated files
python honeyfile_trap.py list

# Step 4: Start monitoring (in one terminal)
python honeyfile_trap.py monitor

# Step 5: In another terminal, trigger an alert by accessing a honeyfile
notepad honeyfiles\passwords.txt  # Windows
# or
cat honeyfiles/passwords.txt      # Linux/macOS
```

### Example 2: Advanced Configuration

```bash
# Interactive configuration setup
python honeyfile_trap.py config --setup

# Generate honeyfiles from specific categories
python honeyfile_trap.py generate --count 20 --categories sensitive financial

# Monitor with custom configuration
python honeyfile_trap.py --config ./config/production_config.yaml monitor
```

### Example 3: Log Analysis and Reporting

```bash
# View recent alerts
python honeyfile_trap.py logs --type alert --limit 25

# Generate comprehensive report
python honeyfile_trap.py report --days 30 --output monthly_report.json

# Export access logs for external analysis
python honeyfile_trap.py export --type access --format csv --output access_analysis.csv
```

## 📝 Configuration Examples

### Basic Configuration (`config/basic_config.yaml`)

```yaml
monitoring:
  enabled: true
  check_interval: 1.0
  recursive: true

honeyfiles:
  directory: "./honeyfiles"
  types: ["txt", "docx", "xlsx", "pdf"]

alerts:
  enabled: true
  sound: false
  terminal_color: true
  log_level: "INFO"

logging:
  enabled: true
  directory: "./logs"
  max_file_size: "5MB"
  backup_count: 3
  encryption: false
  format: "json"

security:
  collect_process_info: true
  collect_user_info: true
  collect_network_info: false

notifications:
  email:
    enabled: false
```

### Production Configuration with Email (`config/production_config.yaml`)

```yaml
monitoring:
  enabled: true
  check_interval: 0.5
  recursive: true

honeyfiles:
  directory: "/var/honeyfiles"
  types: ["txt", "doc", "docx", "pdf", "xls", "xlsx", "ppt", "zip", "rar"]

alerts:
  enabled: true
  sound: true
  terminal_color: true
  log_level: "WARNING"

logging:
  enabled: true
  directory: "/var/log/honeyfile-trap"
  max_file_size: "50MB"
  backup_count: 10
  encryption: true
  format: "json"

security:
  collect_process_info: true
  collect_user_info: true
  collect_network_info: true

notifications:
  email:
    enabled: true
    smtp_server: "smtp.gmail.com"
    smtp_port: 587
    username: "security@company.com"
    password: "app-specific-password"
    recipients: 
      - "admin@company.com"
      - "security-team@company.com"
```

### High-Security Configuration (`config/secure_config.yaml`)

```yaml
monitoring:
  enabled: true
  check_interval: 0.1  # Very frequent monitoring
  recursive: true

honeyfiles:
  directory: "./secure_honeyfiles"
  types: ["txt", "key", "pem", "conf", "cfg", "ini", "env"]

alerts:
  enabled: true
  sound: true
  terminal_color: true
  log_level: "DEBUG"  # Capture everything

logging:
  enabled: true
  directory: "./secure_logs"
  max_file_size: "100MB"
  backup_count: 20
  encryption: true  # Always encrypt in secure environments
  format: "json"

security:
  collect_process_info: true
  collect_user_info: true
  collect_network_info: true  # Full monitoring

notifications:
  email:
    enabled: true
    smtp_server: "internal-smtp.company.com"
    smtp_port: 25
    username: "honeyfile-trap@company.com"
    password: "secure-password"
    recipients: 
      - "incident-response@company.com"
      - "ciso@company.com"
```

## 🎯 Testing Scenarios

### Scenario 1: Basic Intrusion Simulation

```bash
# Terminal 1: Start monitoring
python honeyfile_trap.py monitor

# Terminal 2: Generate test files
python honeyfile_trap.py generate --count 5 --categories sensitive

# Terminal 3: Simulate different types of access
echo "Checking file contents" >> honeyfiles/passwords.txt
type honeyfiles/admin_config.txt  # Windows
cat honeyfiles/database_config.txt  # Linux/macOS
cp honeyfiles/secret_keys.txt /tmp/  # Copy operation
del honeyfiles/backup_codes.txt  # Delete operation (Windows)
rm honeyfiles/backup_codes.txt   # Delete operation (Linux/macOS)
```

### Scenario 2: Advanced Process Monitoring

```bash
# Start monitoring with verbose output
python honeyfile_trap.py --verbose monitor

# Access files with different applications
notepad.exe honeyfiles/confidential_memo.docx  # Windows
gedit honeyfiles/confidential_memo.docx        # Linux
open -a TextEdit honeyfiles/confidential_memo.docx  # macOS

# Use command-line tools
findstr "password" honeyfiles/*.txt  # Windows
grep -r "password" honeyfiles/       # Linux/macOS

# Batch operations
for file in honeyfiles/*.txt; do head -n 1 "$file"; done  # Linux/macOS
forfiles /p honeyfiles /m *.txt /c "cmd /c type @path"   # Windows
```

### Scenario 3: Network-Based Access Testing

```bash
# If honeyfiles are on a network share
# Windows
net use Z: \\server\honeyfiles
type Z:\passwords.txt

# Linux (with CIFS/SMB)
sudo mount -t cifs //server/honeyfiles /mnt/honeyfiles
cat /mnt/honeyfiles/passwords.txt

# SSH/SCP access
scp user@remote:/path/to/honeyfiles/secret.txt ./
ssh user@remote "cat /path/to/honeyfiles/admin_keys.txt"
```

## 📊 Expected Output Examples

### Alert Display Example

```
═══════════════════════════════════════════════
🚨 HONEYFILE ACCESSED!
📁 File: passwords.txt
🔧 Action: accessed
⏰ 2024-03-15 14:32:45
⚙️  Possible processes:
   • PID 2847: notepad.exe (john_user)
   • PID 1234: explorer.exe (john_user)
👤 User: john_user on Windows
🌐 Host: DESKTOP-ABC123 (192.168.1.100)
═══════════════════════════════════════════════
```

### Log Output Example

```json
{
  "event_type": "file_access",
  "timestamp": "2024-03-15T14:32:45.123456",
  "file_path": "./honeyfiles/passwords.txt",
  "file_name": "passwords.txt",
  "access_type": "accessed",
  "severity": "CRITICAL",
  "process_info": {
    "monitor_pid": 12345,
    "monitor_name": "python.exe",
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
    "platform_version": "10.0.19041",
    "home_dir": "C:\\Users\\john_user"
  },
  "network_info": {
    "hostname": "DESKTOP-ABC123",
    "local_ip": "192.168.1.100"
  },
  "hash": "a1b2c3d4e5f6789a"
}
```

### Report Example

```json
{
  "period": {
    "start_date": "2024-03-08T00:00:00",
    "end_date": "2024-03-15T23:59:59",
    "days": 7
  },
  "summary": {
    "total_file_accesses": 23,
    "total_alerts": 18,
    "unique_files_accessed": 8,
    "most_accessed_files": [
      {"file": "passwords.txt", "count": 7},
      {"file": "admin_config.txt", "count": 4},
      {"file": "database_backup.sql", "count": 3}
    ],
    "alert_levels": {
      "CRITICAL": 7,
      "HIGH": 4,
      "MEDIUM": 7
    },
    "access_types": {
      "accessed": 12,
      "modified": 6,
      "opened": 4,
      "deleted": 1
    },
    "hourly_distribution": {
      "09": 3,
      "10": 5,
      "14": 8,
      "15": 4,
      "16": 3
    }
  }
}
```

## 🔧 Troubleshooting Examples

### Debug Mode Usage

```bash
# Enable verbose output for debugging
python honeyfile_trap.py --verbose monitor

# Test configuration validation
python honeyfile_trap.py config --validate

# Check system logs for issues
python honeyfile_trap.py logs --type system --limit 50
```

### Common Issues and Solutions

**Issue**: No alerts when accessing files
```bash
# Check if honeyfiles exist
python honeyfile_trap.py list

# Verify monitoring is active
python honeyfile_trap.py logs --type system --limit 10

# Test with a different file access method
echo "test" > honeyfiles/test_access.txt
```

**Issue**: Configuration errors
```bash
# Validate current configuration
python honeyfile_trap.py config --validate

# Show current configuration
python honeyfile_trap.py config --show

# Reset to default configuration
python honeyfile_trap.py config --reset
```

**Issue**: Email notifications not working
```bash
# Test email configuration in Python
python -c "
import smtplib
from email.mime.text import MIMEText

msg = MIMEText('Test message')
msg['Subject'] = 'Test'
msg['From'] = 'your-email@gmail.com'
msg['To'] = 'recipient@gmail.com'

with smtplib.SMTP('smtp.gmail.com', 587) as server:
    server.starttls()
    server.login('your-email@gmail.com', 'app-password')
    server.send_message(msg)
print('Email sent successfully')
"
```

## 🧪 Automated Testing Scripts

### Test Script 1: Basic Functionality (`test_basic.py`)

```python
#!/usr/bin/env python3
"""Basic functionality test for Honeyfile Trap."""

import os
import sys
import time
import subprocess
import threading

def run_command(cmd):
    """Run a command and return the result."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr

def test_basic_functionality():
    """Test basic system functionality."""
    print("🧪 Testing Basic Functionality...")
    
    # Test 1: Generate honeyfiles
    print("1. Testing honeyfile generation...")
    code, out, err = run_command("python honeyfile_trap.py generate --count 5")
    if code == 0:
        print("   ✅ Honeyfile generation: PASSED")
    else:
        print(f"   ❌ Honeyfile generation: FAILED ({err})")
    
    # Test 2: List honeyfiles
    print("2. Testing honeyfile listing...")
    code, out, err = run_command("python honeyfile_trap.py list")
    if code == 0 and "honeyfiles" in out:
        print("   ✅ Honeyfile listing: PASSED")
    else:
        print(f"   ❌ Honeyfile listing: FAILED ({err})")
    
    # Test 3: Configuration validation
    print("3. Testing configuration validation...")
    code, out, err = run_command("python honeyfile_trap.py config --validate")
    if code == 0:
        print("   ✅ Configuration validation: PASSED")
    else:
        print(f"   ❌ Configuration validation: FAILED ({err})")
    
    # Test 4: Log viewing
    print("4. Testing log viewing...")
    code, out, err = run_command("python honeyfile_trap.py logs --type system --limit 5")
    if code == 0:
        print("   ✅ Log viewing: PASSED")
    else:
        print(f"   ❌ Log viewing: FAILED ({err})")
    
    print("\n✅ Basic functionality tests completed!")

if __name__ == "__main__":
    test_basic_functionality()
```

### Test Script 2: Monitoring Test (`test_monitoring.py`)

```python
#!/usr/bin/env python3
"""Monitoring functionality test for Honeyfile Trap."""

import os
import sys
import time
import threading
import subprocess

class MonitoringTest:
    def __init__(self):
        self.monitoring_process = None
        self.test_results = []
    
    def start_monitoring(self):
        """Start monitoring in background."""
        print("🔍 Starting monitoring...")
        self.monitoring_process = subprocess.Popen([
            "python", "honeyfile_trap.py", "monitor"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(3)  # Give monitor time to start
    
    def stop_monitoring(self):
        """Stop monitoring process."""
        if self.monitoring_process:
            self.monitoring_process.terminate()
            time.sleep(1)
            print("🛑 Monitoring stopped")
    
    def trigger_access_event(self, filename):
        """Trigger a file access event."""
        filepath = f"honeyfiles/{filename}"
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                content = f.read()
            print(f"📂 Accessed: {filename}")
            return True
        return False
    
    def run_monitoring_test(self):
        """Run comprehensive monitoring test."""
        try:
            # Generate test honeyfiles
            print("1. Generating test honeyfiles...")
            subprocess.run([
                "python", "honeyfile_trap.py", "generate", "--count", "3"
            ])
            
            # Start monitoring
            self.start_monitoring()
            
            # Trigger access events
            print("2. Triggering access events...")
            honeyfiles = ["passwords.txt", "admin_config.txt", "confidential.txt"]
            
            for filename in honeyfiles:
                if self.trigger_access_event(filename):
                    time.sleep(2)  # Wait between accesses
            
            # Check logs
            print("3. Checking generated logs...")
            time.sleep(2)
            result = subprocess.run([
                "python", "honeyfile_trap.py", "logs", "--type", "access", "--limit", "10"
            ], capture_output=True, text=True)
            
            if "file_access" in result.stdout:
                print("   ✅ Access events logged successfully")
            else:
                print("   ❌ No access events found in logs")
            
            # Generate report
            print("4. Generating test report...")
            subprocess.run([
                "python", "honeyfile_trap.py", "report", "--days", "1", 
                "--output", "test_report.json"
            ])
            
            if os.path.exists("test_report.json"):
                print("   ✅ Report generated successfully")
            else:
                print("   ❌ Report generation failed")
            
        finally:
            self.stop_monitoring()
        
        print("\n✅ Monitoring test completed!")

if __name__ == "__main__":
    test = MonitoringTest()
    test.run_monitoring_test()
```

## 📋 Performance Testing

### Load Test Script (`performance_test.py`)

```python
#!/usr/bin/env python3
"""Performance testing for Honeyfile Trap."""

import time
import threading
import subprocess
import psutil
import os

class PerformanceTest:
    def __init__(self):
        self.monitoring_process = None
        self.metrics = {}
    
    def measure_resource_usage(self, duration=60):
        """Measure CPU and memory usage over time."""
        if not self.monitoring_process:
            return
        
        process = psutil.Process(self.monitoring_process.pid)
        cpu_samples = []
        memory_samples = []
        
        start_time = time.time()
        while time.time() - start_time < duration:
            try:
                cpu_percent = process.cpu_percent()
                memory_mb = process.memory_info().rss / 1024 / 1024
                
                cpu_samples.append(cpu_percent)
                memory_samples.append(memory_mb)
                
                time.sleep(1)
            except psutil.NoSuchProcess:
                break
        
        self.metrics = {
            'avg_cpu_percent': sum(cpu_samples) / len(cpu_samples),
            'max_cpu_percent': max(cpu_samples),
            'avg_memory_mb': sum(memory_samples) / len(memory_samples),
            'max_memory_mb': max(memory_samples)
        }
    
    def run_performance_test(self):
        """Run comprehensive performance test."""
        print("🚀 Performance Testing...")
        
        # Generate many honeyfiles for stress test
        print("1. Generating honeyfiles for stress test...")
        subprocess.run([
            "python", "honeyfile_trap.py", "generate", "--count", "50"
        ])
        
        # Start monitoring
        print("2. Starting monitoring with performance measurement...")
        self.monitoring_process = subprocess.Popen([
            "python", "honeyfile_trap.py", "monitor"
        ])
        time.sleep(3)
        
        # Start resource measurement in background
        measurement_thread = threading.Thread(
            target=self.measure_resource_usage,
            args=(30,)  # Measure for 30 seconds
        )
        measurement_thread.start()
        
        # Generate file access load
        print("3. Generating file access load...")
        for i in range(20):  # Access files multiple times
            subprocess.run([
                "python", "-c", 
                "import os; [print(open(f).read(100)) for f in os.listdir('honeyfiles') if f.endswith('.txt')][:5]"
            ], capture_output=True)
            time.sleep(1)
        
        # Wait for measurements to complete
        measurement_thread.join()
        
        # Stop monitoring
        self.monitoring_process.terminate()
        
        # Display results
        print("\n📊 Performance Results:")
        print(f"   Average CPU usage: {self.metrics['avg_cpu_percent']:.2f}%")
        print(f"   Peak CPU usage: {self.metrics['max_cpu_percent']:.2f}%")
        print(f"   Average Memory usage: {self.metrics['avg_memory_mb']:.2f} MB")
        print(f"   Peak Memory usage: {self.metrics['max_memory_mb']:.2f} MB")
        
        # Performance thresholds
        if self.metrics['avg_cpu_percent'] < 5:
            print("   ✅ CPU usage: EXCELLENT (< 5%)")
        elif self.metrics['avg_cpu_percent'] < 10:
            print("   ✅ CPU usage: GOOD (< 10%)")
        else:
            print("   ⚠️  CPU usage: HIGH (> 10%)")
        
        if self.metrics['avg_memory_mb'] < 50:
            print("   ✅ Memory usage: EXCELLENT (< 50MB)")
        elif self.metrics['avg_memory_mb'] < 100:
            print("   ✅ Memory usage: GOOD (< 100MB)")
        else:
            print("   ⚠️  Memory usage: HIGH (> 100MB)")

if __name__ == "__main__":
    test = PerformanceTest()
    test.run_performance_test()
```

This comprehensive examples file provides practical usage scenarios, testing scripts, and troubleshooting guides for users to effectively deploy and test the Honeyfile Trap system!