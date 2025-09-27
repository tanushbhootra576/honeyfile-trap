"""
Alert System Module
Real-time terminal alerts with configurable notification levels and formats.
"""

import os
import sys
import time
import smtplib
import threading
from datetime import datetime
from typing import Dict, List, Optional, Callable
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path

# Color support for terminal output
try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)  # Auto-reset colors
    COLORS_AVAILABLE = True
except ImportError:
    # Fallback if colorama is not available
    COLORS_AVAILABLE = False
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ""
    class Back:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = BLACK = RESET = ""
    class Style:
        BRIGHT = DIM = NORMAL = RESET_ALL = ""

from .file_monitor import FileAccessEvent


class AlertLevel:
    """Alert severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Alert:
    """Represents a security alert."""
    
    def __init__(self,
                 title: str,
                 message: str,
                 level: str = AlertLevel.MEDIUM,
                 event: Optional[FileAccessEvent] = None,
                 timestamp: Optional[datetime] = None):
        self.title = title
        self.message = message
        self.level = level
        self.event = event
        self.timestamp = timestamp or datetime.now()
        self.alert_id = f"ALERT_{int(self.timestamp.timestamp() * 1000)}"
    
    def to_dict(self) -> Dict:
        """Convert alert to dictionary format."""
        return {
            'alert_id': self.alert_id,
            'title': self.title,
            'message': self.message,
            'level': self.level,
            'timestamp': self.timestamp.isoformat(),
            'event': self.event.to_dict() if self.event else None
        }
    
    def __str__(self) -> str:
        return f"Alert({self.level}): {self.title}"


class TerminalAlerter:
    """Handles terminal-based alert display with colors and formatting."""
    
    def __init__(self, 
                 use_colors: bool = True,
                 show_timestamps: bool = True,
                 show_separators: bool = True,
                 max_width: int = 80):
        self.use_colors = use_colors and COLORS_AVAILABLE
        self.show_timestamps = show_timestamps
        self.show_separators = show_separators
        self.max_width = max_width
        
        # Color schemes for different alert levels
        self.color_schemes = {
            AlertLevel.LOW: {
                'title': Fore.CYAN + Style.BRIGHT,
                'message': Fore.CYAN,
                'border': Fore.CYAN,
                'icon': '🔵'
            },
            AlertLevel.MEDIUM: {
                'title': Fore.YELLOW + Style.BRIGHT,
                'message': Fore.YELLOW,
                'border': Fore.YELLOW,
                'icon': '🟡'
            },
            AlertLevel.HIGH: {
                'title': Fore.RED + Style.BRIGHT,
                'message': Fore.RED,
                'border': Fore.RED,
                'icon': '🔴'
            },
            AlertLevel.CRITICAL: {
                'title': Back.RED + Fore.WHITE + Style.BRIGHT,
                'message': Fore.RED + Style.BRIGHT,
                'border': Back.RED + Fore.WHITE,
                'icon': '🚨'
            }
        }
    
    def display_alert(self, alert: Alert):
        """Display an alert in the terminal with formatting."""
        scheme = self.color_schemes.get(alert.level, self.color_schemes[AlertLevel.MEDIUM])
        
        if self.show_separators:
            self._print_separator(scheme['border'])
        
        # Alert header with icon and title
        icon = scheme['icon'] if self.use_colors else f"[{alert.level}]"
        title_color = scheme['title'] if self.use_colors else ""
        reset = Style.RESET_ALL if self.use_colors else ""
        
        print(f"{title_color}{icon} {alert.title}{reset}")
        
        # Timestamp
        if self.show_timestamps:
            timestamp_str = alert.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            print(f"⏰ {timestamp_str}")
        
        # Alert message
        message_color = scheme['message'] if self.use_colors else ""
        print(f"{message_color}📋 {alert.message}{reset}")
        
        # Event details if available
        if alert.event:
            self._display_event_details(alert.event, scheme)
        
        if self.show_separators:
            self._print_separator(scheme['border'])
    
    def _display_event_details(self, event: FileAccessEvent, scheme: Dict):
        """Display detailed event information."""
        reset = Style.RESET_ALL if self.use_colors else ""
        color = scheme['message'] if self.use_colors else ""
        
        print(f"{color}📁 File: {Path(event.file_path).name}{reset}")
        print(f"{color}🔧 Action: {event.event_type}{reset}")
        
        # Process information
        if event.process_info and 'possible_accessing_processes' in event.process_info:
            processes = event.process_info['possible_accessing_processes'][:3]  # Show top 3
            if processes:
                print(f"{color}⚙️  Possible processes:{reset}")
                for proc in processes:
                    print(f"   • PID {proc['pid']}: {proc['name']} ({proc.get('username', 'unknown')})")
        
        # User information
        if event.user_info and 'username' in event.user_info:
            username = event.user_info['username']
            platform_info = event.user_info.get('platform', 'Unknown')
            print(f"{color}👤 User: {username} on {platform_info}{reset}")
        
        # Network information (if available)
        if event.network_info and 'hostname' in event.network_info:
            hostname = event.network_info['hostname']
            local_ip = event.network_info.get('local_ip', 'unknown')
            print(f"{color}🌐 Host: {hostname} ({local_ip}){reset}")
    
    def _print_separator(self, color: str = ""):
        """Print a separator line."""
        reset = Style.RESET_ALL if self.use_colors else ""
        separator = "═" * min(self.max_width, 60)
        print(f"{color}{separator}{reset}")
    
    def display_banner(self):
        """Display the application banner."""
        banner = f"""
{Fore.YELLOW + Style.BRIGHT if self.use_colors else ""}
🍯 HONEYFILE TRAP - INTRUSION DETECTION SYSTEM
═══════════════════════════════════════════════
{Style.RESET_ALL if self.use_colors else ""}
Status: {Fore.GREEN}ACTIVE{Style.RESET_ALL if self.use_colors else ""}
Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
{Fore.CYAN}Press Ctrl+C to stop monitoring{Style.RESET_ALL if self.use_colors else ""}
"""
        print(banner)
    
    def display_summary(self, stats: Dict):
        """Display monitoring statistics."""
        color = Fore.CYAN if self.use_colors else ""
        reset = Style.RESET_ALL if self.use_colors else ""
        
        print(f"\n{color}📊 MONITORING STATISTICS{reset}")
        print(f"   Files monitored: {stats.get('monitored_files_count', 0)}")
        print(f"   Queue size: {stats.get('queue_size', 0)}")
        print(f"   Status: {'Running' if stats.get('is_running', False) else 'Stopped'}")


class EmailAlerter:
    """Handles email-based notifications."""
    
    def __init__(self,
                 smtp_server: str,
                 smtp_port: int,
                 username: str,
                 password: str,
                 recipients: List[str]):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.recipients = recipients
        self.enabled = bool(smtp_server and username and recipients)
    
    def send_alert(self, alert: Alert) -> bool:
        """Send alert via email."""
        if not self.enabled:
            return False
        
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.username
            msg['To'] = ', '.join(self.recipients)
            msg['Subject'] = f"[HONEYFILE TRAP] {alert.level} Alert: {alert.title}"
            
            # Create email body
            body = self._create_email_body(alert)
            msg.attach(MIMEText(body, 'html'))
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.send_message(msg)
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to send email alert: {e}")
            return False
    
    def _create_email_body(self, alert: Alert) -> str:
        """Create HTML email body."""
        level_colors = {
            AlertLevel.LOW: '#17a2b8',
            AlertLevel.MEDIUM: '#ffc107',
            AlertLevel.HIGH: '#dc3545',
            AlertLevel.CRITICAL: '#721c24'
        }
        
        color = level_colors.get(alert.level, '#6c757d')
        
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .alert-header {{ background-color: {color}; color: white; padding: 15px; border-radius: 5px; }}
                .alert-content {{ background-color: #f8f9fa; padding: 20px; margin: 10px 0; border-radius: 5px; }}
                .event-details {{ background-color: #e9ecef; padding: 10px; margin: 10px 0; border-radius: 3px; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="alert-header">
                <h2>🍯 Honeyfile Trap Alert</h2>
                <p><strong>Level:</strong> {alert.level}</p>
                <p><strong>Time:</strong> {alert.timestamp.strftime("%Y-%m-%d %H:%M:%S")}</p>
            </div>
            
            <div class="alert-content">
                <h3>{alert.title}</h3>
                <p>{alert.message}</p>
        """
        
        if alert.event:
            html += f"""
                <div class="event-details">
                    <h4>Event Details</h4>
                    <table>
                        <tr><th>File Path</th><td>{alert.event.file_path}</td></tr>
                        <tr><th>Event Type</th><td>{alert.event.event_type}</td></tr>
                        <tr><th>Timestamp</th><td>{alert.event.timestamp.strftime("%Y-%m-%d %H:%M:%S")}</td></tr>
            """
            
            if alert.event.user_info and 'username' in alert.event.user_info:
                html += f"<tr><th>User</th><td>{alert.event.user_info['username']}</td></tr>"
            
            if alert.event.process_info and 'possible_accessing_processes' in alert.event.process_info:
                processes = alert.event.process_info['possible_accessing_processes'][:3]
                if processes:
                    process_list = "<br>".join([f"PID {p['pid']}: {p['name']}" for p in processes])
                    html += f"<tr><th>Processes</th><td>{process_list}</td></tr>"
            
            html += """
                    </table>
                </div>
            """
        
        html += """
            </div>
            <p><em>This alert was generated by Honeyfile Trap Intrusion Detection System.</em></p>
        </body>
        </html>
        """
        
        return html


class AlertManager:
    """Main alert management system."""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        
        # Initialize alerters
        self.terminal_alerter = TerminalAlerter(
            use_colors=self.config.get('terminal_color', True),
            show_timestamps=True,
            show_separators=True
        )
        
        # Email alerter (optional)
        email_config = self.config.get('email', {})
        if email_config.get('enabled', False):
            self.email_alerter = EmailAlerter(
                smtp_server=email_config.get('smtp_server', ''),
                smtp_port=email_config.get('smtp_port', 587),
                username=email_config.get('username', ''),
                password=email_config.get('password', ''),
                recipients=email_config.get('recipients', [])
            )
        else:
            self.email_alerter = None
        
        # Alert history
        self.alert_history: List[Alert] = []
        self.max_history = 100
        
        # Alert callbacks
        self.alert_callbacks: List[Callable[[Alert], None]] = []
        
        # Sound support (basic)
        self.sound_enabled = self.config.get('sound', False)
    
    def add_alert_callback(self, callback: Callable[[Alert], None]):
        """Add a callback function for alerts."""
        self.alert_callbacks.append(callback)
    
    def create_file_access_alert(self, event: FileAccessEvent) -> Alert:
        """Create an alert for file access events."""
        filename = Path(event.file_path).name
        
        # Determine alert level based on file type and access pattern
        level = self._determine_alert_level(event)
        
        title = f"Honeyfile Accessed: {filename}"
        
        message = (f"Suspicious activity detected! "
                  f"The honeyfile '{filename}' was {event.event_type} "
                  f"at {event.timestamp.strftime('%H:%M:%S')}.")
        
        return Alert(
            title=title,
            message=message,
            level=level,
            event=event
        )
    
    def _determine_alert_level(self, event: FileAccessEvent) -> str:
        """Determine alert level based on event characteristics."""
        filename = Path(event.file_path).name.lower()
        
        # Critical files
        if any(keyword in filename for keyword in ['password', 'secret', 'key', 'credential']):
            return AlertLevel.CRITICAL
        
        # High priority files
        if any(keyword in filename for keyword in ['admin', 'config', 'database', 'backup']):
            return AlertLevel.HIGH
        
        # Medium priority (financial, corporate)
        if any(keyword in filename for keyword in ['financial', 'payroll', 'budget', 'employee']):
            return AlertLevel.MEDIUM
        
        # Default
        return AlertLevel.MEDIUM
    
    def send_alert(self, alert: Alert):
        """Send an alert through all configured channels."""
        # Add to history
        self.alert_history.append(alert)
        if len(self.alert_history) > self.max_history:
            self.alert_history.pop(0)
        
        # Terminal alert (always shown)
        self.terminal_alerter.display_alert(alert)
        
        # Email alert (if configured)
        if self.email_alerter:
            threading.Thread(
                target=self.email_alerter.send_alert,
                args=(alert,),
                daemon=True
            ).start()
        
        # Sound alert (if enabled)
        if self.sound_enabled:
            self._play_sound(alert.level)
        
        # Custom callbacks
        for callback in self.alert_callbacks:
            try:
                threading.Thread(
                    target=callback,
                    args=(alert,),
                    daemon=True
                ).start()
            except Exception as e:
                print(f"❌ Error in alert callback: {e}")
    
    def _play_sound(self, level: str):
        """Play sound alert (basic implementation)."""
        try:
            if sys.platform.startswith('win'):
                # Windows
                import winsound
                frequency = {
                    AlertLevel.LOW: 800,
                    AlertLevel.MEDIUM: 1000,
                    AlertLevel.HIGH: 1200,
                    AlertLevel.CRITICAL: 1500
                }.get(level, 1000)
                
                duration = 200 if level == AlertLevel.CRITICAL else 100
                winsound.Beep(frequency, duration)
                
            else:
                # Unix-like systems
                os.system('printf "\\a"')  # Terminal bell
                
        except Exception:
            # Fallback: just print a sound indicator
            print("🔔 *BEEP*")
    
    def display_banner(self):
        """Display the application banner."""
        self.terminal_alerter.display_banner()
    
    def display_statistics(self, stats: Dict):
        """Display monitoring statistics."""
        self.terminal_alerter.display_summary(stats)
        
        # Add alert statistics
        if self.alert_history:
            print(f"   Recent alerts: {len(self.alert_history)}")
            
            # Count by level
            level_counts = {}
            for alert in self.alert_history[-10:]:  # Last 10 alerts
                level_counts[alert.level] = level_counts.get(alert.level, 0) + 1
            
            for level, count in level_counts.items():
                print(f"     {level}: {count}")
    
    def get_recent_alerts(self, count: int = 10) -> List[Alert]:
        """Get recent alerts."""
        return self.alert_history[-count:] if self.alert_history else []


def demo_alert_callback(alert: Alert):
    """Demo callback for custom alert handling."""
    print(f"📝 Custom Alert Handler: {alert.title} ({alert.level})")


def main():
    """Demo function for testing the alert system."""
    from .file_monitor import FileAccessEvent
    
    # Create alert manager
    config = {
        'terminal_color': True,
        'sound': False,
        'email': {'enabled': False}
    }
    
    alert_manager = AlertManager(config)
    alert_manager.add_alert_callback(demo_alert_callback)
    
    # Display banner
    alert_manager.display_banner()
    
    # Create demo events and alerts
    demo_events = [
        FileAccessEvent("./honeyfiles/passwords.txt", "accessed"),
        FileAccessEvent("./honeyfiles/financial_report.pdf", "modified"),
        FileAccessEvent("./honeyfiles/admin_config.txt", "opened"),
    ]
    
    print("🧪 Testing alert system with demo events...")
    print()
    
    for event in demo_events:
        alert = alert_manager.create_file_access_alert(event)
        alert_manager.send_alert(alert)
        time.sleep(2)  # Pause between alerts
    
    # Display statistics
    stats = {
        'is_running': True,
        'monitored_files_count': 5,
        'queue_size': 0
    }
    alert_manager.display_statistics(stats)


if __name__ == "__main__":
    main()