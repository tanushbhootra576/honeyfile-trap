"""
Honeyfile Trap - Main CLI Interface
Terminal-based cybersecurity intrusion detection tool using honeyfiles.
"""

import os
import sys
import time
import signal
import argparse
from pathlib import Path
from datetime import datetime, timedelta
import json

# Add src to path for local imports

sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.honeyfile_generator import HoneyfileGenerator
from src.file_monitor import FileMonitor
from src.alert_system import AlertManager
from src.incident_logger import IncidentLogger, LogAnalyzer
from src.log_encryption import LogEncryption, setup_encryption
from src.config_manager import ConfigManager, interactive_config_setup


class HoneyfileTrap:
    """Main application class for the Honeyfile Trap system."""
    
    def __init__(self, config_file: str = None):
        """Initialize the Honeyfile Trap system."""
        self.config_file = config_file or "./config/config.yaml"
        self.config_manager = ConfigManager(self.config_file)
        
        # Initialize components
        self.honeyfile_generator = None
        self.file_monitor = None
        self.alert_manager = None
        self.incident_logger = None
        self.log_encryption = None
        
        # Runtime state
        self.is_running = False
        self.start_time = None
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def initialize(self) -> bool:
        """Initialize all system components."""
        print("🍯 Initializing Honeyfile Trap System...")
        
        # Load configuration
        if not self.config_manager.load_config():
            print("❌ Failed to load configuration")
            return False
        
        config = self.config_manager.config
        
        # Validate configuration
        issues = self.config_manager.validate_config()
        if issues:
            print("⚠️  Configuration Issues:")
            for issue in issues:
                print(f"   • {issue}")
            if not self._ask_continue():
                return False
        
        try:
            # Initialize honeyfile generator
            self.honeyfile_generator = HoneyfileGenerator(
                output_dir=config.honeyfiles.directory
            )
            
            # Initialize log encryption (if enabled)
            if config.logging.encryption:
                print("🔐 Setting up log encryption...")
                key_file = Path(config.logging.directory) / "encryption_key.json"
                self.log_encryption = LogEncryption(
                    encryption_method="symmetric",
                    key_file=str(key_file)
                )
            
            # Initialize incident logger
            self.incident_logger = IncidentLogger(
                log_directory=config.logging.directory,
                max_file_size=config.logging.max_file_size,
                backup_count=config.logging.backup_count,
                log_format=config.logging.format
            )
            
            # Initialize alert manager
            alert_config = {
                'terminal_color': config.alerts.terminal_color,
                'sound': config.alerts.sound,
                'email': {
                    'enabled': config.notifications.email.enabled,
                    'smtp_server': config.notifications.email.smtp_server,
                    'smtp_port': config.notifications.email.smtp_port,
                    'username': config.notifications.email.username,
                    'password': config.notifications.email.password,
                    'recipients': config.notifications.email.recipients
                }
            }
            
            self.alert_manager = AlertManager(alert_config)
            
            # Initialize file monitor
            self.file_monitor = FileMonitor(
                honeyfile_directory=config.honeyfiles.directory,
                check_interval=config.monitoring.check_interval,
                collect_process_info=config.security.collect_process_info,
                collect_user_info=config.security.collect_user_info,
                collect_network_info=config.security.collect_network_info
            )
            
            # Wire up event handlers
            self.file_monitor.add_event_callback(self._handle_file_access)
            
            print("✅ System initialized successfully")
            return True
            
        except Exception as e:
            print(f"❌ Failed to initialize system: {e}")
            return False
    
    def _handle_file_access(self, event):
        """Handle file access events."""
        try:
            # Log the event
            if self.incident_logger:
                self.incident_logger.log_file_access(event)
            
            # Create and send alert
            if self.alert_manager:
                alert = self.alert_manager.create_file_access_alert(event)
                self.alert_manager.send_alert(alert)
                
                # Log the alert
                if self.incident_logger:
                    self.incident_logger.log_alert(alert)
                    
        except Exception as e:
            print(f"❌ Error handling file access event: {e}")
    
    def _signal_handler(self, signum, frame):
        """Handle system signals (Ctrl+C, etc.)."""
        print(f"\n🛑 Received signal {signum}")
        self.stop()
    
    def _ask_continue(self) -> bool:
        """Ask user if they want to continue despite issues."""
        try:
            return input("Continue anyway? (y/N): ").lower().startswith('y')
        except KeyboardInterrupt:
            return False
    
    def start_monitoring(self) -> bool:
        """Start the monitoring system."""
        if self.is_running:
            print("⚠️  System is already running")
            return False
        
        if not self.file_monitor:
            print("❌ System not initialized")
            return False
        
        # Log system startup
        if self.incident_logger:
            self.incident_logger.log_system_event(
                "startup",
                "Honeyfile Trap monitoring started",
                {"config_file": str(self.config_file)}
            )
        
        # Display banner
        if self.alert_manager:
            self.alert_manager.display_banner()
        
        # Start monitoring
        if self.file_monitor.start_monitoring():
            self.is_running = True
            self.start_time = datetime.now()
            
            try:
                # Main monitoring loop
                while self.is_running:
                    time.sleep(1)
                    
                    # Display periodic statistics (every 5 minutes)
                    if datetime.now().second == 0 and datetime.now().minute % 5 == 0:
                        self._display_status()
            
            except KeyboardInterrupt:
                print("\n🛑 Interrupted by user")
            
            return True
        
        else:
            print("❌ Failed to start monitoring")
            return False
    
    def stop(self):
        """Stop the monitoring system."""
        if not self.is_running:
            return
        
        print("🛑 Stopping Honeyfile Trap...")
        
        self.is_running = False
        
        if self.file_monitor:
            self.file_monitor.stop_monitoring()
        
        # Log system shutdown
        if self.incident_logger:
            runtime = datetime.now() - self.start_time if self.start_time else timedelta(0)
            self.incident_logger.log_system_event(
                "shutdown",
                "Honeyfile Trap monitoring stopped",
                {"runtime_seconds": runtime.total_seconds()}
            )
        
        print("✅ System stopped")
    
    def _display_status(self):
        """Display system status and statistics."""
        if not self.file_monitor or not self.alert_manager:
            return
        
        stats = self.file_monitor.get_statistics()
        self.alert_manager.display_statistics(stats)
    
    def generate_honeyfiles(self, count: int = 10, categories: list = None) -> bool:
        """Generate honeyfiles."""
        if not self.honeyfile_generator:
            print("❌ Honeyfile generator not initialized")
            return False
        
        print(f"🍯 Generating {count} honeyfiles...")
        
        try:
            files = self.honeyfile_generator.generate_honeyfarm(
                count=count,
                categories=categories
            )
            
            print(f"✅ Successfully generated {len(files)} honeyfiles")
            
            # Log the generation
            if self.incident_logger:
                self.incident_logger.log_system_event(
                    "honeyfile_generation",
                    f"Generated {len(files)} honeyfiles",
                    {
                        "count": len(files),
                        "categories": categories or "all",
                        "files": [f.name for f in files]
                    }
                )
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to generate honeyfiles: {e}")
            return False
    
    def list_honeyfiles(self):
        """List existing honeyfiles."""
        if not self.honeyfile_generator:
            print("❌ Honeyfile generator not initialized")
            return
        
        files = self.honeyfile_generator.list_honeyfiles()
        
        if not files:
            print("📂 No honeyfiles found")
            return
        
        print(f"📂 Found {len(files)} honeyfiles:")
        for file_path in sorted(files):
            stat = file_path.stat()
            size = stat.st_size
            modified = datetime.fromtimestamp(stat.st_mtime)
            print(f"   • {file_path.name} ({size} bytes, modified {modified.strftime('%Y-%m-%d %H:%M')})")
    
    def clear_honeyfiles(self) -> bool:
        """Clear all honeyfiles."""
        if not self.honeyfile_generator:
            print("❌ Honeyfile generator not initialized")
            return False
        
        if not self._ask_continue_clear():
            print("❌ Operation cancelled")
            return False
        
        count = self.honeyfile_generator.clear_all_honeyfiles()
        print(f"🗑️  Removed {count} honeyfiles")
        
        # Log the clearing
        if self.incident_logger:
            self.incident_logger.log_system_event(
                "honeyfiles_cleared",
                f"Cleared {count} honeyfiles",
                {"count": count}
            )
        
        return True
    
    def _ask_continue_clear(self) -> bool:
        """Ask user to confirm clearing honeyfiles."""
        try:
            return input("⚠️  This will delete all honeyfiles. Continue? (y/N): ").lower().startswith('y')
        except KeyboardInterrupt:
            return False
    
    def show_logs(self, log_type: str = "access", limit: int = 10, days: int = None):
        """Display recent logs."""
        if not self.incident_logger:
            print("❌ Incident logger not initialized")
            return
        
        start_date = None
        if days:
            start_date = datetime.now() - timedelta(days=days)
        
        logs = self.incident_logger.get_logs(log_type, start_date, limit=limit)
        
        if not logs:
            print(f"📋 No {log_type} logs found")
            return
        
        print(f"📋 Recent {log_type} logs ({len(logs)} entries):")
        print("-" * 80)
        
        for log in logs[-limit:]:  # Show most recent
            timestamp = log.get('timestamp', 'unknown')
            if log_type == "access":
                file_name = log.get('file_name', 'unknown')
                access_type = log.get('access_type', 'unknown')
                severity = log.get('severity', 'unknown')
                print(f"[{timestamp}] {severity} - {file_name} ({access_type})")
            
            elif log_type == "alert":
                title = log.get('title', 'unknown')
                level = log.get('level', 'unknown')
                print(f"[{timestamp}] {level} - {title}")
            
            elif log_type == "system":
                system_event_type = log.get('system_event_type', 'unknown')
                message = log.get('message', 'unknown')
                print(f"[{timestamp}] SYSTEM - {system_event_type}: {message}")
    
    def generate_report(self, days: int = 7, output_file: str = None):
        """Generate and display/save a summary report."""
        if not self.incident_logger:
            print("❌ Incident logger not initialized")
            return
        
        print(f"📊 Generating report for the last {days} days...")
        
        analyzer = LogAnalyzer(self.incident_logger)
        report = analyzer.generate_summary_report(days)
        
        # Display summary
        summary = report['summary']
        print(f"\n📈 SUMMARY REPORT ({days} days)")
        print("=" * 50)
        print(f"File accesses: {summary['total_file_accesses']}")
        print(f"Alerts generated: {summary['total_alerts']}")
        print(f"Unique files accessed: {summary['unique_files_accessed']}")
        
        if summary['most_accessed_files']:
            print(f"\nMost accessed files:")
            for item in summary['most_accessed_files']:
                print(f"   • {item['file']} ({item['count']} times)")
        
        if summary['alert_levels']:
            print(f"\nAlert levels:")
            for level, count in summary['alert_levels'].items():
                print(f"   • {level}: {count}")
        
        # Save to file if requested
        if output_file:
            try:
                output_path = Path(output_file)
                output_path.parent.mkdir(exist_ok=True)
                
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(report, f, indent=2, ensure_ascii=False)
                
                print(f"\n💾 Report saved to {output_path}")
                
            except Exception as e:
                print(f"❌ Failed to save report: {e}")
    
    def export_logs(self, log_type: str = "access", format: str = "json", output_file: str = None):
        """Export logs to file."""
        if not self.incident_logger:
            print("❌ Incident logger not initialized")
            return
        
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"./logs/export_{log_type}_{timestamp}.{format}"
        
        success = self.incident_logger.export_logs(
            output_file=output_file,
            log_type=log_type,
            format=format
        )
        
        if success:
            print(f"✅ Logs exported successfully")
        else:
            print(f"❌ Failed to export logs")


def create_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Honeyfile Trap - Terminal-based Cybersecurity Intrusion Detection Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s monitor                    # Start monitoring
  %(prog)s generate --count 15        # Generate 15 honeyfiles
  %(prog)s list                       # List existing honeyfiles
  %(prog)s logs --type alert --limit 20   # Show 20 recent alerts
  %(prog)s report --days 30           # Generate 30-day report
  %(prog)s config --setup             # Interactive configuration setup
        """
    )
    
    parser.add_argument(
        '--config', '-c',
        default='./config/config.yaml',
        help='Configuration file path (default: ./config/config.yaml)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Monitor command
    monitor_parser = subparsers.add_parser(
        'monitor',
        help='Start file monitoring'
    )
    
    # Generate command
    generate_parser = subparsers.add_parser(
        'generate',
        help='Generate honeyfiles'
    )
    generate_parser.add_argument(
        '--count', '-n',
        type=int,
        default=10,
        help='Number of honeyfiles to generate (default: 10)'
    )
    generate_parser.add_argument(
        '--categories',
        nargs='+',
        choices=['sensitive', 'financial', 'corporate', 'personal'],
        help='Categories of honeyfiles to generate'
    )
    
    # List command
    list_parser = subparsers.add_parser(
        'list',
        help='List existing honeyfiles'
    )
    
    # Clear command
    clear_parser = subparsers.add_parser(
        'clear',
        help='Remove all honeyfiles'
    )
    
    # Logs command
    logs_parser = subparsers.add_parser(
        'logs',
        help='Display recent logs'
    )
    logs_parser.add_argument(
        '--type', '-t',
        choices=['access', 'alert', 'system'],
        default='access',
        help='Type of logs to display (default: access)'
    )
    logs_parser.add_argument(
        '--limit', '-l',
        type=int,
        default=10,
        help='Number of log entries to display (default: 10)'
    )
    logs_parser.add_argument(
        '--days', '-d',
        type=int,
        help='Only show logs from the last N days'
    )
    
    # Report command
    report_parser = subparsers.add_parser(
        'report',
        help='Generate summary report'
    )
    report_parser.add_argument(
        '--days', '-d',
        type=int,
        default=7,
        help='Number of days to include in report (default: 7)'
    )
    report_parser.add_argument(
        '--output', '-o',
        help='Save report to file'
    )
    
    # Export command
    export_parser = subparsers.add_parser(
        'export',
        help='Export logs to file'
    )
    export_parser.add_argument(
        '--type', '-t',
        choices=['access', 'alert', 'system'],
        default='access',
        help='Type of logs to export (default: access)'
    )
    export_parser.add_argument(
        '--format', '-f',
        choices=['json', 'csv', 'txt'],
        default='json',
        help='Export format (default: json)'
    )
    export_parser.add_argument(
        '--output', '-o',
        help='Output file path'
    )
    
    # Config command
    config_parser = subparsers.add_parser(
        'config',
        help='Configuration management'
    )
    config_parser.add_argument(
        '--setup', '-s',
        action='store_true',
        help='Interactive configuration setup'
    )
    config_parser.add_argument(
        '--show',
        action='store_true',
        help='Show current configuration'
    )
    config_parser.add_argument(
        '--validate',
        action='store_true',
        help='Validate configuration'
    )
    config_parser.add_argument(
        '--reset',
        action='store_true',
        help='Reset to default configuration'
    )
    
    return parser


def main():
    """Main entry point for the application."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Handle config-only operations first
    if args.command == 'config':
        if args.setup:
            config_manager = interactive_config_setup()
            return
        
        config_manager = ConfigManager(args.config)
        
        if args.show:
            config_manager.load_config()
            config_manager.print_config()
            return
        
        if args.validate:
            config_manager.load_config()
            issues = config_manager.validate_config()
            if issues:
                print("⚠️  Configuration Issues:")
                for issue in issues:
                    print(f"   • {issue}")
            else:
                print("✅ Configuration is valid")
            return
        
        if args.reset:
            if config_manager.reset_to_defaults():
                print("✅ Configuration reset to defaults")
            else:
                print("❌ Failed to reset configuration")
            return
    
    # For other commands, initialize the main system
    try:
        # Create and initialize the Honeyfile Trap system
        trap = HoneyfileTrap(args.config)
        
        if not trap.initialize():
            sys.exit(1)
        
        # Execute the requested command
        if args.command == 'monitor' or args.command is None:
            trap.start_monitoring()
        
        elif args.command == 'generate':
            trap.generate_honeyfiles(args.count, args.categories)
        
        elif args.command == 'list':
            trap.list_honeyfiles()
        
        elif args.command == 'clear':
            trap.clear_honeyfiles()
        
        elif args.command == 'logs':
            trap.show_logs(args.type, args.limit, args.days)
        
        elif args.command == 'report':
            trap.generate_report(args.days, args.output)
        
        elif args.command == 'export':
            trap.export_logs(args.type, args.format, args.output)
        
        else:
            parser.print_help()
    
    except KeyboardInterrupt:
        print("\n🛑 Interrupted by user")
        sys.exit(0)
    
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()