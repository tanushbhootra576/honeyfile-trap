"""
Honeyfile Trap Package Initialization
"""

from .honeyfile_generator import HoneyfileGenerator
from .file_monitor import FileMonitor, FileAccessEvent
from .alert_system import AlertManager, Alert, AlertLevel
from .incident_logger import IncidentLogger, LogAnalyzer
from .log_encryption import LogEncryption
from .config_manager import ConfigManager

__version__ = "1.0.0"
__author__ = "Honeyfile Trap Project"
__description__ = "Terminal-based cybersecurity intrusion detection tool using honeyfiles"

__all__ = [
    'HoneyfileGenerator',
    'FileMonitor',
    'FileAccessEvent',
    'AlertManager',
    'Alert',
    'AlertLevel',
    'IncidentLogger',
    'LogAnalyzer',
    'LogEncryption',
    'ConfigManager'
]