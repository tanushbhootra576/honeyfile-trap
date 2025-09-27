"""
File Monitor Module
Cross-platform file access monitoring for honeyfiles using watchdog and system APIs.
"""

import os
import sys
import time
import psutil
import platform
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Callable, Set
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading
import queue
import socket


class FileAccessEvent:
    """Represents a file access event with metadata."""
    
    def __init__(self, 
                 file_path: str,
                 event_type: str,
                 timestamp: datetime = None,
                 process_info: Dict = None,
                 user_info: Dict = None,
                 network_info: Dict = None):
        self.file_path = file_path
        self.event_type = event_type  # 'accessed', 'modified', 'opened', 'deleted'
        self.timestamp = timestamp or datetime.now()
        self.process_info = process_info or {}
        self.user_info = user_info or {}
        self.network_info = network_info or {}
    
    def to_dict(self) -> Dict:
        """Convert event to dictionary format."""
        return {
            'file_path': self.file_path,
            'event_type': self.event_type,
            'timestamp': self.timestamp.isoformat(),
            'process_info': self.process_info,
            'user_info': self.user_info,
            'network_info': self.network_info
        }
    
    def __str__(self) -> str:
        return f"FileAccessEvent({self.file_path}, {self.event_type}, {self.timestamp})"


class HoneyfileEventHandler(FileSystemEventHandler):
    """Custom event handler for monitoring honeyfile access."""
    
    def __init__(self, 
                 monitored_files: Set[str], 
                 event_queue: queue.Queue,
                 collect_process_info: bool = True,
                 collect_user_info: bool = True,
                 collect_network_info: bool = False):
        super().__init__()
        self.monitored_files = monitored_files
        self.event_queue = event_queue
        self.collect_process_info = collect_process_info
        self.collect_user_info = collect_user_info
        self.collect_network_info = collect_network_info
        self.last_events = {}  # Debounce duplicate events
    
    def on_modified(self, event):
        if not event.is_directory and event.src_path in self.monitored_files:
            self._handle_file_event(event.src_path, 'modified')
    
    def on_accessed(self, event):
        if not event.is_directory and event.src_path in self.monitored_files:
            self._handle_file_event(event.src_path, 'accessed')
    
    def on_opened(self, event):
        if not event.is_directory and event.src_path in self.monitored_files:
            self._handle_file_event(event.src_path, 'opened')
    
    def on_deleted(self, event):
        if not event.is_directory and event.src_path in self.monitored_files:
            self._handle_file_event(event.src_path, 'deleted')
    
    def _handle_file_event(self, file_path: str, event_type: str):
        """Handle file access event with debouncing."""
        current_time = time.time()
        event_key = f"{file_path}_{event_type}"
        
        # Debounce: ignore events within 1 second of the same file/event type
        if event_key in self.last_events:
            if current_time - self.last_events[event_key] < 1.0:
                return
        
        self.last_events[event_key] = current_time
        
        # Collect metadata
        process_info = self._collect_process_info() if self.collect_process_info else {}
        user_info = self._collect_user_info() if self.collect_user_info else {}
        network_info = self._collect_network_info() if self.collect_network_info else {}
        
        # Create event
        event_obj = FileAccessEvent(
            file_path=file_path,
            event_type=event_type,
            process_info=process_info,
            user_info=user_info,
            network_info=network_info
        )
        
        # Queue the event
        try:
            self.event_queue.put_nowait(event_obj)
        except queue.Full:
            # If queue is full, remove oldest item and add new one
            try:
                self.event_queue.get_nowait()
                self.event_queue.put_nowait(event_obj)
            except queue.Empty:
                pass
    
    def _collect_process_info(self) -> Dict:
        """Collect information about accessing process."""
        try:
            # Get current process (this is the monitor process)
            # In a real-world scenario, you'd need more sophisticated methods
            # to determine which process actually accessed the file
            current_process = psutil.Process()
            
            # Try to find processes that might have accessed the file recently
            accessing_processes = []
            
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
                try:
                    proc_info = proc.info
                    if proc_info['name'] and proc_info['name'] not in ['System', 'Registry']:
                        accessing_processes.append({
                            'pid': proc_info['pid'],
                            'name': proc_info['name'],
                            'username': proc_info['username'],
                            'cmdline': ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else ''
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            # Return the most likely candidates (limit to 5 most recent)
            return {
                'monitor_pid': current_process.pid,
                'monitor_name': current_process.name(),
                'possible_accessing_processes': accessing_processes[:5]
            }
            
        except Exception as e:
            return {'error': f'Could not collect process info: {str(e)}'}
    
    def _collect_user_info(self) -> Dict:
        """Collect user information."""
        try:
            return {
                'username': os.getlogin() if hasattr(os, 'getlogin') else os.environ.get('USER', 'unknown'),
                'uid': os.getuid() if hasattr(os, 'getuid') else None,
                'gid': os.getgid() if hasattr(os, 'getgid') else None,
                'home_dir': os.path.expanduser('~'),
                'platform': platform.system(),
                'platform_version': platform.version()
            }
        except Exception as e:
            return {'error': f'Could not collect user info: {str(e)}'}
    
    def _collect_network_info(self) -> Dict:
        """Collect network information (if enabled)."""
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            
            # Get active network connections
            connections = []
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == psutil.CONN_ESTABLISHED:
                    connections.append({
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status,
                        'pid': conn.pid
                    })
            
            return {
                'hostname': hostname,
                'local_ip': local_ip,
                'active_connections': connections[:10]  # Limit to 10 connections
            }
        except Exception as e:
            return {'error': f'Could not collect network info: {str(e)}'}


class FileMonitor:
    """Main file monitor class that orchestrates the monitoring system."""
    
    def __init__(self, 
                 honeyfile_directory: str = "./honeyfiles",
                 check_interval: float = 1.0,
                 collect_process_info: bool = True,
                 collect_user_info: bool = True,
                 collect_network_info: bool = False):
        
        self.honeyfile_directory = Path(honeyfile_directory)
        self.check_interval = check_interval
        self.collect_process_info = collect_process_info
        self.collect_user_info = collect_user_info
        self.collect_network_info = collect_network_info
        
        self.observer = None
        self.event_queue = queue.Queue(maxsize=1000)
        self.monitored_files: Set[str] = set()
        self.is_running = False
        self.event_callbacks: List[Callable[[FileAccessEvent], None]] = []
        
        # Threading
        self.monitor_thread = None
        self.event_processor_thread = None
        self._stop_event = threading.Event()
        
        print(f"🔍 File Monitor initialized")
        print(f"   Directory: {self.honeyfile_directory.absolute()}")
        print(f"   Check interval: {self.check_interval}s")
    
    def add_event_callback(self, callback: Callable[[FileAccessEvent], None]):
        """Add a callback function to be called when file events occur."""
        self.event_callbacks.append(callback)
    
    def start_monitoring(self) -> bool:
        """Start the file monitoring system."""
        try:
            if self.is_running:
                print("⚠️  Monitor is already running")
                return False
            
            # Ensure honeyfile directory exists
            self.honeyfile_directory.mkdir(exist_ok=True)
            
            # Scan for existing honeyfiles
            self._scan_honeyfiles()
            
            if not self.monitored_files:
                print("⚠️  No honeyfiles found to monitor")
                return False
            
            # Create and configure the observer
            event_handler = HoneyfileEventHandler(
                monitored_files=self.monitored_files,
                event_queue=self.event_queue,
                collect_process_info=self.collect_process_info,
                collect_user_info=self.collect_user_info,
                collect_network_info=self.collect_network_info
            )
            
            self.observer = Observer()
            self.observer.schedule(
                event_handler, 
                str(self.honeyfile_directory), 
                recursive=False
            )
            
            # Start the observer
            self.observer.start()
            
            # Start event processor thread
            self.event_processor_thread = threading.Thread(
                target=self._process_events,
                daemon=True
            )
            self.event_processor_thread.start()
            
            self.is_running = True
            
            print(f"✅ File monitor started successfully")
            print(f"   Monitoring {len(self.monitored_files)} honeyfiles")
            print(f"   Press Ctrl+C to stop monitoring")
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to start monitoring: {e}")
            return False
    
    def stop_monitoring(self):
        """Stop the file monitoring system."""
        if not self.is_running:
            return
        
        print("🛑 Stopping file monitor...")
        
        self.is_running = False
        self._stop_event.set()
        
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=5)
        
        if self.event_processor_thread and self.event_processor_thread.is_alive():
            self.event_processor_thread.join(timeout=5)
        
        print("✅ File monitor stopped")
    
    def _scan_honeyfiles(self):
        """Scan the honeyfile directory for files to monitor."""
        self.monitored_files.clear()
        
        if not self.honeyfile_directory.exists():
            return
        
        for file_path in self.honeyfile_directory.iterdir():
            if file_path.is_file():
                self.monitored_files.add(str(file_path.absolute()))
        
        print(f"📋 Found {len(self.monitored_files)} honeyfiles to monitor:")
        for file_path in sorted(self.monitored_files):
            print(f"   • {Path(file_path).name}")
    
    def _process_events(self):
        """Process file access events from the queue."""
        while self.is_running and not self._stop_event.is_set():
            try:
                # Wait for events with timeout
                event = self.event_queue.get(timeout=1)
                
                # Call all registered callbacks
                for callback in self.event_callbacks:
                    try:
                        callback(event)
                    except Exception as e:
                        print(f"❌ Error in event callback: {e}")
                
                # Mark task as done
                self.event_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                print(f"❌ Error processing events: {e}")
                time.sleep(1)
    
    def get_statistics(self) -> Dict:
        """Get monitoring statistics."""
        return {
            'is_running': self.is_running,
            'monitored_files_count': len(self.monitored_files),
            'queue_size': self.event_queue.qsize(),
            'honeyfile_directory': str(self.honeyfile_directory.absolute())
        }
    
    def refresh_honeyfiles(self):
        """Refresh the list of honeyfiles to monitor."""
        print("🔄 Refreshing honeyfile list...")
        old_count = len(self.monitored_files)
        self._scan_honeyfiles()
        new_count = len(self.monitored_files)
        
        if new_count != old_count:
            print(f"   File count changed: {old_count} → {new_count}")
        else:
            print("   No changes detected")


def demo_event_handler(event: FileAccessEvent):
    """Demo event handler for testing."""
    print(f"🚨 HONEYFILE ACCESSED!")
    print(f"   File: {Path(event.file_path).name}")
    print(f"   Type: {event.event_type}")
    print(f"   Time: {event.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
    
    if event.process_info:
        print(f"   Process Info: {event.process_info}")
    
    if event.user_info:
        username = event.user_info.get('username', 'unknown')
        platform_info = event.user_info.get('platform', 'unknown')
        print(f"   User: {username} on {platform_info}")
    
    print("-" * 50)


def main():
    """Demo function for testing the file monitor."""
    # Create a monitor instance
    monitor = FileMonitor(
        honeyfile_directory="./honeyfiles",
        collect_process_info=True,
        collect_user_info=True,
        collect_network_info=False
    )
    
    # Add demo event handler
    monitor.add_event_callback(demo_event_handler)
    
    try:
        # Start monitoring
        if monitor.start_monitoring():
            # Keep running until interrupted
            while monitor.is_running:
                time.sleep(1)
        else:
            print("Failed to start monitoring")
    
    except KeyboardInterrupt:
        print("\n🛑 Interrupted by user")
    
    finally:
        monitor.stop_monitoring()


if __name__ == "__main__":
    main()