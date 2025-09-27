"""
Configuration Management Module
Handles loading, validation, and management of application configuration.
"""

import os
import yaml
import json
from pathlib import Path
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass, asdict
import shutil


@dataclass
class MonitoringConfig:
    """Monitoring configuration settings."""
    enabled: bool = True
    check_interval: float = 1.0
    recursive: bool = True


@dataclass
class HoneyfileConfig:
    """Honeyfile configuration settings."""
    directory: str = "./honeyfiles"
    types: List[str] = None
    
    def __post_init__(self):
        if self.types is None:
            self.types = ["txt", "doc", "docx", "pdf", "xls", "xlsx", "ppt", "pptx", "zip", "rar"]


@dataclass
class AlertConfig:
    """Alert system configuration settings."""
    enabled: bool = True
    sound: bool = False
    terminal_color: bool = True
    log_level: str = "INFO"


@dataclass
class LoggingConfig:
    """Logging configuration settings."""
    enabled: bool = True
    directory: str = "./logs"
    max_file_size: str = "10MB"
    backup_count: int = 5
    encryption: bool = False
    format: str = "json"  # json, csv, text


@dataclass
class SecurityConfig:
    """Security-related configuration settings."""
    collect_process_info: bool = True
    collect_user_info: bool = True
    collect_network_info: bool = False


@dataclass
class EmailConfig:
    """Email notification configuration."""
    enabled: bool = False
    smtp_server: str = ""
    smtp_port: int = 587
    username: str = ""
    password: str = ""
    recipients: List[str] = None
    
    def __post_init__(self):
        if self.recipients is None:
            self.recipients = []


@dataclass
class NotificationConfig:
    """Notification configuration container."""
    email: EmailConfig = None
    
    def __post_init__(self):
        if self.email is None:
            self.email = EmailConfig()


@dataclass
class Config:
    """Main configuration container."""
    monitoring: MonitoringConfig = None
    honeyfiles: HoneyfileConfig = None
    alerts: AlertConfig = None
    logging: LoggingConfig = None
    security: SecurityConfig = None
    notifications: NotificationConfig = None
    
    def __post_init__(self):
        if self.monitoring is None:
            self.monitoring = MonitoringConfig()
        if self.honeyfiles is None:
            self.honeyfiles = HoneyfileConfig()
        if self.alerts is None:
            self.alerts = AlertConfig()
        if self.logging is None:
            self.logging = LoggingConfig()
        if self.security is None:
            self.security = SecurityConfig()
        if self.notifications is None:
            self.notifications = NotificationConfig()


class ConfigManager:
    """Manages application configuration loading, validation, and persistence."""
    
    def __init__(self, config_file: Union[str, Path] = "./config/config.yaml"):
        self.config_file = Path(config_file)
        self.config: Config = Config()
        self._default_config = Config()
        
        print(f"⚙️  Configuration Manager initialized")
        print(f"   Config file: {self.config_file.absolute()}")
    
    def load_config(self) -> bool:
        """Load configuration from file."""
        if not self.config_file.exists():
            print(f"⚠️  Config file not found: {self.config_file}")
            print("   Creating default configuration...")
            return self.create_default_config()
        
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                if self.config_file.suffix.lower() == '.json':
                    data = json.load(f)
                else:
                    data = yaml.safe_load(f)
            
            self.config = self._dict_to_config(data)
            print("✅ Configuration loaded successfully")
            return True
            
        except Exception as e:
            print(f"❌ Failed to load configuration: {e}")
            print("   Using default configuration...")
            self.config = Config()
            return False
    
    def save_config(self) -> bool:
        """Save current configuration to file."""
        try:
            # Ensure config directory exists
            self.config_file.parent.mkdir(exist_ok=True)
            
            # Convert config to dictionary
            config_dict = self._config_to_dict(self.config)
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                if self.config_file.suffix.lower() == '.json':
                    json.dump(config_dict, f, indent=2)
                else:
                    yaml.dump(config_dict, f, default_flow_style=False, sort_keys=False)
            
            print(f"✅ Configuration saved to {self.config_file}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to save configuration: {e}")
            return False
    
    def create_default_config(self) -> bool:
        """Create and save default configuration."""
        self.config = Config()
        return self.save_config()
    
    def backup_config(self, backup_suffix: str = None) -> bool:
        """Create a backup of the current configuration file."""
        if not self.config_file.exists():
            print("❌ No configuration file to backup")
            return False
        
        try:
            if backup_suffix is None:
                from datetime import datetime
                backup_suffix = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            backup_file = self.config_file.with_name(
                f"{self.config_file.stem}_backup_{backup_suffix}{self.config_file.suffix}"
            )
            
            shutil.copy2(self.config_file, backup_file)
            print(f"✅ Configuration backed up to {backup_file}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to backup configuration: {e}")
            return False
    
    def validate_config(self) -> List[str]:
        """Validate configuration and return list of issues."""
        issues = []
        
        # Validate monitoring settings
        if self.config.monitoring.check_interval <= 0:
            issues.append("Monitoring check_interval must be positive")
        
        # Validate honeyfile directory
        honeyfile_dir = Path(self.config.honeyfiles.directory)
        if not honeyfile_dir.is_absolute() and not (Path.cwd() / honeyfile_dir).parent.exists():
            issues.append(f"Honeyfiles directory parent doesn't exist: {honeyfile_dir}")
        
        # Validate logging directory
        log_dir = Path(self.config.logging.directory)
        if not log_dir.is_absolute() and not (Path.cwd() / log_dir).parent.exists():
            issues.append(f"Logging directory parent doesn't exist: {log_dir}")
        
        # Validate file size format
        try:
            self._parse_size(self.config.logging.max_file_size)
        except:
            issues.append(f"Invalid max_file_size format: {self.config.logging.max_file_size}")
        
        # Validate email configuration
        if self.config.notifications.email.enabled:
            email_config = self.config.notifications.email
            if not email_config.smtp_server:
                issues.append("Email enabled but no SMTP server specified")
            if not email_config.username:
                issues.append("Email enabled but no username specified")
            if not email_config.recipients:
                issues.append("Email enabled but no recipients specified")
            if not (1 <= email_config.smtp_port <= 65535):
                issues.append(f"Invalid SMTP port: {email_config.smtp_port}")
        
        # Validate log format
        valid_formats = ["json", "csv", "text"]
        if self.config.logging.format not in valid_formats:
            issues.append(f"Invalid logging format: {self.config.logging.format}. Must be one of: {valid_formats}")
        
        # Validate alert log level
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self.config.alerts.log_level not in valid_levels:
            issues.append(f"Invalid log level: {self.config.alerts.log_level}. Must be one of: {valid_levels}")
        
        return issues
    
    def get_setting(self, key_path: str, default: Any = None) -> Any:
        """Get a configuration setting using dot notation (e.g., 'monitoring.enabled')."""
        try:
            keys = key_path.split('.')
            value = self.config
            
            for key in keys:
                if hasattr(value, key):
                    value = getattr(value, key)
                else:
                    return default
            
            return value
            
        except Exception:
            return default
    
    def set_setting(self, key_path: str, value: Any) -> bool:
        """Set a configuration setting using dot notation."""
        try:
            keys = key_path.split('.')
            target = self.config
            
            # Navigate to the parent object
            for key in keys[:-1]:
                if hasattr(target, key):
                    target = getattr(target, key)
                else:
                    return False
            
            # Set the final value
            final_key = keys[-1]
            if hasattr(target, final_key):
                setattr(target, final_key, value)
                return True
            else:
                return False
                
        except Exception:
            return False
    
    def _dict_to_config(self, data: Dict[str, Any]) -> Config:
        """Convert dictionary to Config object."""
        config = Config()
        
        # Monitoring
        if 'monitoring' in data:
            config.monitoring = MonitoringConfig(**data['monitoring'])
        
        # Honeyfiles
        if 'honeyfiles' in data:
            config.honeyfiles = HoneyfileConfig(**data['honeyfiles'])
        
        # Alerts
        if 'alerts' in data:
            config.alerts = AlertConfig(**data['alerts'])
        
        # Logging
        if 'logging' in data:
            config.logging = LoggingConfig(**data['logging'])
        
        # Security
        if 'security' in data:
            config.security = SecurityConfig(**data['security'])
        
        # Notifications
        if 'notifications' in data:
            notifications = data['notifications']
            email_config = EmailConfig(**notifications.get('email', {}))
            config.notifications = NotificationConfig(email=email_config)
        
        return config
    
    def _config_to_dict(self, config: Config) -> Dict[str, Any]:
        """Convert Config object to dictionary."""
        return {
            'monitoring': asdict(config.monitoring),
            'honeyfiles': asdict(config.honeyfiles),
            'alerts': asdict(config.alerts),
            'logging': asdict(config.logging),
            'security': asdict(config.security),
            'notifications': {
                'email': asdict(config.notifications.email)
            }
        }
    
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
    
    def print_config(self):
        """Print current configuration in a readable format."""
        print("\n📋 Current Configuration:")
        print("=" * 50)
        
        print(f"\n🔍 Monitoring:")
        print(f"   Enabled: {self.config.monitoring.enabled}")
        print(f"   Check interval: {self.config.monitoring.check_interval}s")
        print(f"   Recursive: {self.config.monitoring.recursive}")
        
        print(f"\n🍯 Honeyfiles:")
        print(f"   Directory: {self.config.honeyfiles.directory}")
        print(f"   File types: {', '.join(self.config.honeyfiles.types)}")
        
        print(f"\n⚠️  Alerts:")
        print(f"   Enabled: {self.config.alerts.enabled}")
        print(f"   Sound: {self.config.alerts.sound}")
        print(f"   Terminal colors: {self.config.alerts.terminal_color}")
        print(f"   Log level: {self.config.alerts.log_level}")
        
        print(f"\n📋 Logging:")
        print(f"   Enabled: {self.config.logging.enabled}")
        print(f"   Directory: {self.config.logging.directory}")
        print(f"   Format: {self.config.logging.format}")
        print(f"   Max file size: {self.config.logging.max_file_size}")
        print(f"   Backup count: {self.config.logging.backup_count}")
        print(f"   Encryption: {self.config.logging.encryption}")
        
        print(f"\n🔐 Security:")
        print(f"   Collect process info: {self.config.security.collect_process_info}")
        print(f"   Collect user info: {self.config.security.collect_user_info}")
        print(f"   Collect network info: {self.config.security.collect_network_info}")
        
        print(f"\n📧 Email Notifications:")
        print(f"   Enabled: {self.config.notifications.email.enabled}")
        if self.config.notifications.email.enabled:
            print(f"   SMTP Server: {self.config.notifications.email.smtp_server}:{self.config.notifications.email.smtp_port}")
            print(f"   Username: {self.config.notifications.email.username}")
            print(f"   Recipients: {len(self.config.notifications.email.recipients)} configured")
    
    def export_config(self, output_file: str, format: str = "yaml") -> bool:
        """Export configuration to a file in specified format."""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(exist_ok=True)
            
            config_dict = self._config_to_dict(self.config)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                if format.lower() == 'json':
                    json.dump(config_dict, f, indent=2)
                else:
                    yaml.dump(config_dict, f, default_flow_style=False, sort_keys=False)
            
            print(f"✅ Configuration exported to {output_path}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to export configuration: {e}")
            return False
    
    def reset_to_defaults(self) -> bool:
        """Reset configuration to default values."""
        print("🔄 Resetting configuration to defaults...")
        self.config = Config()
        return self.save_config()


def interactive_config_setup() -> ConfigManager:
    """Interactive configuration setup wizard."""
    print("🧙 Honeyfile Trap Configuration Wizard")
    print("=" * 40)
    
    config_manager = ConfigManager()
    
    # Load existing config or create default
    config_manager.load_config()
    
    print("\n🔍 Monitoring Configuration:")
    enable_monitoring = input(f"Enable monitoring? [{config_manager.config.monitoring.enabled}]: ")
    if enable_monitoring.lower() in ['n', 'no', 'false']:
        config_manager.config.monitoring.enabled = False
    
    if config_manager.config.monitoring.enabled:
        interval = input(f"Check interval (seconds) [{config_manager.config.monitoring.check_interval}]: ")
        try:
            if interval:
                config_manager.config.monitoring.check_interval = float(interval)
        except ValueError:
            print("⚠️  Invalid interval, using default")
    
    print("\n🍯 Honeyfile Configuration:")
    honeyfile_dir = input(f"Honeyfiles directory [{config_manager.config.honeyfiles.directory}]: ")
    if honeyfile_dir:
        config_manager.config.honeyfiles.directory = honeyfile_dir
    
    print("\n⚠️  Alert Configuration:")
    enable_sound = input(f"Enable sound alerts? [{config_manager.config.alerts.sound}]: ")
    if enable_sound.lower() in ['y', 'yes', 'true']:
        config_manager.config.alerts.sound = True
    
    print("\n📧 Email Notification Configuration:")
    enable_email = input(f"Enable email notifications? [{config_manager.config.notifications.email.enabled}]: ")
    if enable_email.lower() in ['y', 'yes', 'true']:
        config_manager.config.notifications.email.enabled = True
        
        smtp_server = input("SMTP server: ")
        if smtp_server:
            config_manager.config.notifications.email.smtp_server = smtp_server
        
        smtp_port = input("SMTP port [587]: ")
        try:
            if smtp_port:
                config_manager.config.notifications.email.smtp_port = int(smtp_port)
        except ValueError:
            print("⚠️  Invalid port, using default")
        
        username = input("Username: ")
        if username:
            config_manager.config.notifications.email.username = username
        
        recipients = input("Recipients (comma-separated): ")
        if recipients:
            config_manager.config.notifications.email.recipients = [
                email.strip() for email in recipients.split(',')
            ]
    
    print("\n🔐 Security Configuration:")
    enable_encryption = input(f"Enable log encryption? [{config_manager.config.logging.encryption}]: ")
    if enable_encryption.lower() in ['y', 'yes', 'true']:
        config_manager.config.logging.encryption = True
    
    # Validate configuration
    issues = config_manager.validate_config()
    if issues:
        print("\n⚠️  Configuration Issues:")
        for issue in issues:
            print(f"   • {issue}")
        
        if input("\nContinue anyway? (y/N): ").lower().startswith('y'):
            pass
        else:
            print("Configuration not saved.")
            return None
    
    # Save configuration
    if config_manager.save_config():
        print("\n✅ Configuration saved successfully!")
        config_manager.print_config()
    else:
        print("\n❌ Failed to save configuration")
    
    return config_manager


def main():
    """Demo function for testing configuration management."""
    print("🧪 Testing Configuration Management...")
    
    # Create config manager
    config_manager = ConfigManager("./config/test_config.yaml")
    
    # Load or create config
    config_manager.load_config()
    
    # Print current configuration
    config_manager.print_config()
    
    # Validate configuration
    issues = config_manager.validate_config()
    if issues:
        print("\n⚠️  Configuration Issues:")
        for issue in issues:
            print(f"   • {issue}")
    else:
        print("\n✅ Configuration is valid")
    
    # Test setting values
    print("\n🔧 Testing configuration modification...")
    config_manager.set_setting("monitoring.check_interval", 2.5)
    config_manager.set_setting("alerts.sound", True)
    
    print(f"Monitoring interval: {config_manager.get_setting('monitoring.check_interval')}")
    print(f"Sound alerts: {config_manager.get_setting('alerts.sound')}")
    
    # Export configuration
    config_manager.export_config("./config/exported_config.json", "json")
    
    print("\n✅ Configuration management test completed")


if __name__ == "__main__":
    main()