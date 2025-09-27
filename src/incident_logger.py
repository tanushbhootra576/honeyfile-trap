"""
Logging System Module
Comprehensive incident logging with metadata collection and optional encryption.
"""

import os
import json
import gzip
import hashlib
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
import logging
from logging.handlers import RotatingFileHandler
import csv

from .file_monitor import FileAccessEvent
from .alert_system import Alert


class IncidentLogger:
    """Handles structured logging of security incidents with metadata."""
    
    def __init__(self,
                 log_directory: str = "./logs",
                 max_file_size: str = "10MB",
                 backup_count: int = 5,
                 log_format: str = "json",  # json, csv, text
                 compress_old_logs: bool = True):
        
        self.log_directory = Path(log_directory)
        self.log_directory.mkdir(exist_ok=True)
        
        self.max_file_size = self._parse_size(max_file_size)
        self.backup_count = backup_count
        self.log_format = log_format
        self.compress_old_logs = compress_old_logs
        
        # Create different log files for different types of events
        self.loggers = self._setup_loggers()
        
        # Thread safety
        self._lock = threading.Lock()
        
        print(f"📋 Incident Logger initialized")
        print(f"   Directory: {self.log_directory.absolute()}")
        print(f"   Format: {log_format}")
        print(f"   Max size: {max_file_size}")
    
    def _parse_size(self, size_str: str) -> int:
        """Parse size string (e.g., '10MB') to bytes."""
        size_str = size_str.upper()
        if size_str.endswith('KB'):
            return int(size_str[:-2]) * 1024
        elif size_str.endswith('MB'):
            return int(size_str[:-2]) * 1024 * 1024
        elif size_str.endswith('GB'):
            return int(size_str[:-2]) * 1024 * 1024 * 1024
        else:
            return int(size_str)
    
    def _setup_loggers(self) -> Dict[str, logging.Logger]:
        """Set up different loggers for different event types."""
        loggers = {}
        
        # File access events logger
        access_logger = logging.getLogger('honeyfile_access')
        access_logger.setLevel(logging.INFO)
        
        access_handler = RotatingFileHandler(
            self.log_directory / f"file_access.{self.log_format}",
            maxBytes=self.max_file_size,
            backupCount=self.backup_count
        )
        
        # Alert events logger
        alert_logger = logging.getLogger('honeyfile_alerts')
        alert_logger.setLevel(logging.INFO)
        
        alert_handler = RotatingFileHandler(
            self.log_directory / f"alerts.{self.log_format}",
            maxBytes=self.max_file_size,
            backupCount=self.backup_count
        )
        
        # System events logger
        system_logger = logging.getLogger('honeyfile_system')
        system_logger.setLevel(logging.INFO)
        
        system_handler = RotatingFileHandler(
            self.log_directory / f"system.{self.log_format}",
            maxBytes=self.max_file_size,
            backupCount=self.backup_count
        )
        
        # Custom formatter based on log format
        if self.log_format == "json":
            formatter = JsonFormatter()
        elif self.log_format == "csv":
            formatter = CsvFormatter()
        else:
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
        
        for handler in [access_handler, alert_handler, system_handler]:
            handler.setFormatter(formatter)
        
        access_logger.addHandler(access_handler)
        alert_logger.addHandler(alert_handler)
        system_logger.addHandler(system_handler)
        
        # Prevent duplicate logs
        access_logger.propagate = False
        alert_logger.propagate = False
        system_logger.propagate = False
        
        return {
            'access': access_logger,
            'alert': alert_logger,
            'system': system_logger
        }
    
    def log_file_access(self, event: FileAccessEvent):
        """Log a file access event."""
        with self._lock:
            log_data = {
                'event_type': 'file_access',
                'timestamp': event.timestamp.isoformat(),
                'file_path': event.file_path,
                'file_name': Path(event.file_path).name,
                'access_type': event.event_type,
                'process_info': event.process_info,
                'user_info': event.user_info,
                'network_info': event.network_info,
                'severity': self._calculate_severity(event),
                'hash': self._generate_event_hash(event)
            }
            
            self.loggers['access'].info(json.dumps(log_data) if self.log_format != "json" else log_data)
    
    def log_alert(self, alert: Alert):
        """Log an alert event."""
        with self._lock:
            log_data = {
                'event_type': 'alert',
                'timestamp': alert.timestamp.isoformat(),
                'alert_id': alert.alert_id,
                'title': alert.title,
                'message': alert.message,
                'level': alert.level,
                'file_path': alert.event.file_path if alert.event else None,
                'file_name': Path(alert.event.file_path).name if alert.event else None,
                'process_info': alert.event.process_info if alert.event else None,
                'user_info': alert.event.user_info if alert.event else None,
                'network_info': alert.event.network_info if alert.event else None
            }
            
            self.loggers['alert'].info(json.dumps(log_data) if self.log_format != "json" else log_data)
    
    def log_system_event(self, event_type: str, message: str, details: Dict = None):
        """Log a system event."""
        with self._lock:
            log_data = {
                'event_type': 'system',
                'system_event_type': event_type,
                'timestamp': datetime.now().isoformat(),
                'message': message,
                'details': details or {}
            }
            
            self.loggers['system'].info(json.dumps(log_data) if self.log_format != "json" else log_data)
    
    def _calculate_severity(self, event: FileAccessEvent) -> str:
        """Calculate event severity based on file characteristics."""
        filename = Path(event.file_path).name.lower()
        
        # Critical keywords
        if any(keyword in filename for keyword in ['password', 'secret', 'key', 'credential']):
            return 'CRITICAL'
        
        # High priority keywords
        if any(keyword in filename for keyword in ['admin', 'config', 'database', 'backup']):
            return 'HIGH'
        
        # Medium priority keywords
        if any(keyword in filename for keyword in ['financial', 'payroll', 'employee', 'confidential']):
            return 'MEDIUM'
        
        return 'LOW'
    
    def _generate_event_hash(self, event: FileAccessEvent) -> str:
        """Generate a unique hash for the event."""
        hash_data = f"{event.file_path}_{event.event_type}_{event.timestamp.isoformat()}"
        return hashlib.sha256(hash_data.encode()).hexdigest()[:16]
    
    def get_logs(self, 
                 log_type: str = "access",
                 start_date: Optional[datetime] = None,
                 end_date: Optional[datetime] = None,
                 limit: int = 100) -> List[Dict]:
        """Retrieve logs with filtering options."""
        log_file = self.log_directory / f"{log_type}.{self.log_format}"
        
        if not log_file.exists():
            return []
        
        logs = []
        
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if not line.strip():
                        continue
                    
                    try:
                        if self.log_format == "json":
                            log_entry = json.loads(line)
                        else:
                            # For other formats, assume JSON-encoded message
                            log_parts = line.strip().split(' - ')
                            if len(log_parts) >= 4:
                                log_entry = json.loads(' - '.join(log_parts[3:]))
                            else:
                                continue
                        
                        # Filter by date if specified
                        if start_date or end_date:
                            log_time = datetime.fromisoformat(log_entry['timestamp'])
                            if start_date and log_time < start_date:
                                continue
                            if end_date and log_time > end_date:
                                continue
                        
                        logs.append(log_entry)
                        
                        if len(logs) >= limit:
                            break
                            
                    except (json.JSONDecodeError, KeyError, ValueError):
                        continue
        
        except Exception as e:
            print(f"❌ Error reading logs: {e}")
            return []
        
        return logs[-limit:]  # Return most recent entries
    
    def get_statistics(self) -> Dict:
        """Get logging statistics."""
        stats = {
            'log_directory': str(self.log_directory.absolute()),
            'log_format': self.log_format,
            'log_files': {},
            'total_size': 0
        }
        
        for log_type in ['access', 'alert', 'system']:
            log_file = self.log_directory / f"{log_type}.{self.log_format}"
            if log_file.exists():
                file_size = log_file.stat().st_size
                stats['log_files'][log_type] = {
                    'size_bytes': file_size,
                    'size_mb': round(file_size / 1024 / 1024, 2),
                    'last_modified': datetime.fromtimestamp(
                        log_file.stat().st_mtime
                    ).isoformat()
                }
                stats['total_size'] += file_size
        
        stats['total_size_mb'] = round(stats['total_size'] / 1024 / 1024, 2)
        
        return stats
    
    def export_logs(self, 
                   output_file: str,
                   log_type: str = "access",
                   format: str = "json",
                   start_date: Optional[datetime] = None,
                   end_date: Optional[datetime] = None) -> bool:
        """Export logs to a file in specified format."""
        try:
            logs = self.get_logs(log_type, start_date, end_date, limit=10000)
            
            output_path = Path(output_file)
            output_path.parent.mkdir(exist_ok=True)
            
            if format.lower() == "json":
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(logs, f, indent=2, ensure_ascii=False)
            
            elif format.lower() == "csv":
                if not logs:
                    return False
                
                with open(output_path, 'w', newline='', encoding='utf-8') as f:
                    fieldnames = logs[0].keys()
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    for log in logs:
                        # Flatten nested dictionaries
                        flattened_log = self._flatten_dict(log)
                        writer.writerow(flattened_log)
            
            elif format.lower() == "txt":
                with open(output_path, 'w', encoding='utf-8') as f:
                    for log in logs:
                        f.write(f"{json.dumps(log, indent=2)}\n\n")
            
            print(f"✅ Exported {len(logs)} log entries to {output_path}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to export logs: {e}")
            return False
    
    def _flatten_dict(self, d: Dict, parent_key: str = '', sep: str = '_') -> Dict:
        """Flatten nested dictionary for CSV export."""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                items.append((new_key, json.dumps(v)))
            else:
                items.append((new_key, v))
        return dict(items)
    
    def cleanup_old_logs(self, days_to_keep: int = 30) -> int:
        """Clean up old log files. Returns count of files removed."""
        cutoff_date = datetime.now() - timedelta(days=days_to_keep)
        removed_count = 0
        
        for log_file in self.log_directory.glob("*.log*"):
            try:
                file_mtime = datetime.fromtimestamp(log_file.stat().st_mtime)
                if file_mtime < cutoff_date:
                    log_file.unlink()
                    removed_count += 1
                    print(f"🗑️  Removed old log file: {log_file.name}")
            except Exception as e:
                print(f"❌ Error removing log file {log_file.name}: {e}")
        
        return removed_count


class JsonFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""
    
    def format(self, record):
        if hasattr(record, 'msg') and isinstance(record.msg, dict):
            return json.dumps(record.msg)
        else:
            log_entry = {
                'timestamp': datetime.fromtimestamp(record.created).isoformat(),
                'level': record.levelname,
                'logger': record.name,
                'message': str(record.getMessage())
            }
            return json.dumps(log_entry)


class CsvFormatter(logging.Formatter):
    """Custom CSV formatter (outputs JSON that can be parsed later)."""
    
    def format(self, record):
        # For CSV, we still output JSON but mark it for CSV processing
        if hasattr(record, 'msg') and isinstance(record.msg, dict):
            return json.dumps(record.msg)
        else:
            log_entry = {
                'timestamp': datetime.fromtimestamp(record.created).isoformat(),
                'level': record.levelname,
                'logger': record.name,
                'message': str(record.getMessage())
            }
            return json.dumps(log_entry)


class LogAnalyzer:
    """Analyzes logs for patterns and generates reports."""
    
    def __init__(self, incident_logger: IncidentLogger):
        self.incident_logger = incident_logger
    
    def generate_summary_report(self, days: int = 7) -> Dict:
        """Generate a summary report for the specified number of days."""
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        # Get logs for the period
        access_logs = self.incident_logger.get_logs(
            "access", start_date, end_date, limit=10000
        )
        alert_logs = self.incident_logger.get_logs(
            "alert", start_date, end_date, limit=10000
        )
        
        report = {
            'period': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat(),
                'days': days
            },
            'summary': {
                'total_file_accesses': len(access_logs),
                'total_alerts': len(alert_logs),
                'unique_files_accessed': len(set(log.get('file_name', '') for log in access_logs if log.get('file_name'))),
                'most_accessed_files': self._get_most_accessed_files(access_logs),
                'alert_levels': self._count_alert_levels(alert_logs),
                'access_types': self._count_access_types(access_logs),
                'hourly_distribution': self._get_hourly_distribution(access_logs)
            }
        }
        
        return report
    
    def _get_most_accessed_files(self, logs: List[Dict], limit: int = 5) -> List[Dict]:
        """Get most frequently accessed files."""
        file_counts = {}
        for log in logs:
            file_name = log.get('file_name', '')
            if file_name:
                file_counts[file_name] = file_counts.get(file_name, 0) + 1
        
        sorted_files = sorted(file_counts.items(), key=lambda x: x[1], reverse=True)
        return [{'file': file, 'count': count} for file, count in sorted_files[:limit]]
    
    def _count_alert_levels(self, logs: List[Dict]) -> Dict:
        """Count alerts by level."""
        level_counts = {}
        for log in logs:
            level = log.get('level', 'UNKNOWN')
            level_counts[level] = level_counts.get(level, 0) + 1
        return level_counts
    
    def _count_access_types(self, logs: List[Dict]) -> Dict:
        """Count accesses by type."""
        type_counts = {}
        for log in logs:
            access_type = log.get('access_type', 'UNKNOWN')
            type_counts[access_type] = type_counts.get(access_type, 0) + 1
        return type_counts
    
    def _get_hourly_distribution(self, logs: List[Dict]) -> Dict:
        """Get hourly distribution of access events."""
        hourly_counts = {str(i).zfill(2): 0 for i in range(24)}
        
        for log in logs:
            try:
                timestamp = datetime.fromisoformat(log['timestamp'])
                hour = str(timestamp.hour).zfill(2)
                hourly_counts[hour] += 1
            except (KeyError, ValueError):
                continue
        
        return hourly_counts


def main():
    """Demo function for testing the logging system."""
    from .file_monitor import FileAccessEvent
    from .alert_system import Alert, AlertLevel
    
    # Create incident logger
    logger = IncidentLogger(
        log_directory="./logs",
        max_file_size="1MB",
        log_format="json"
    )
    
    print("🧪 Testing logging system...")
    
    # Create demo events
    demo_event = FileAccessEvent(
        file_path="./honeyfiles/passwords.txt",
        event_type="accessed",
        process_info={'pid': 1234, 'name': 'notepad.exe'},
        user_info={'username': 'testuser', 'platform': 'Windows'}
    )
    
    demo_alert = Alert(
        title="Critical File Access",
        message="Password file was accessed",
        level=AlertLevel.CRITICAL,
        event=demo_event
    )
    
    # Log events
    logger.log_file_access(demo_event)
    logger.log_alert(demo_alert)
    logger.log_system_event("startup", "Honeyfile monitoring started")
    
    # Show statistics
    stats = logger.get_statistics()
    print("\n📊 Logging Statistics:")
    print(json.dumps(stats, indent=2))
    
    # Generate report
    analyzer = LogAnalyzer(logger)
    report = analyzer.generate_summary_report(days=1)
    print("\n📈 Summary Report:")
    print(json.dumps(report, indent=2))
    
    print("\n✅ Logging system test completed")


if __name__ == "__main__":
    main()