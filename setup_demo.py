#!/usr/bin/env python3
"""
Quick setup and demonstration script for Honeyfile Trap.
Run this to quickly set up and test the system.
"""

import os
import sys
import time
import subprocess
from pathlib import Path


def run_command(cmd, capture=True):
    """Run a command and optionally capture output."""
    if capture:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.returncode == 0, result.stdout, result.stderr
    else:
        return subprocess.run(cmd, shell=True).returncode == 0, "", ""


def print_header(title):
    """Print a formatted header."""
    print(f"\n{'='*60}")
    print(f"🍯 {title}")
    print(f"{'='*60}")


def print_step(step, description):
    """Print a step description."""
    print(f"\n{step}. {description}")


def main():
    """Main setup and demo function."""
    print_header("HONEYFILE TRAP - QUICK SETUP & DEMO")
    print("This script will set up and demonstrate the Honeyfile Trap system.")
    
    # Check if we're in the right directory
    if not Path("honeyfile_trap.py").exists():
        print("❌ Error: honeyfile_trap.py not found. Please run this script from the project root.")
        return
    
    try:
        print_step(1, "Installing Dependencies")
        success, out, err = run_command("pip install -r requirements.txt")
        if success:
            print("✅ Dependencies installed successfully")
        else:
            print(f"❌ Failed to install dependencies: {err}")
            return
        
        print_step(2, "Setting Up Configuration")
        success, out, err = run_command("python honeyfile_trap.py config --validate")
        if not success:
            print("📝 Creating default configuration...")
            run_command("python honeyfile_trap.py config --show")
        print("✅ Configuration ready")
        
        print_step(3, "Generating Demo Honeyfiles")
        success, out, err = run_command("python honeyfile_trap.py generate --count 8")
        if success:
            print("✅ Generated demo honeyfiles")
            
            # Show the generated files
            success, out, err = run_command("python honeyfile_trap.py list")
            if success:
                print("📂 Generated honeyfiles:")
                print(out)
        else:
            print(f"❌ Failed to generate honeyfiles: {err}")
            return
        
        print_step(4, "Testing System Components")
        
        # Test logging
        success, out, err = run_command("python honeyfile_trap.py logs --type system --limit 5")
        if success:
            print("✅ Logging system working")
        
        # Test configuration
        success, out, err = run_command("python honeyfile_trap.py config --validate")
        if success:
            print("✅ Configuration validation working")
        
        print_step(5, "Demo Instructions")
        print("""
🎯 To test the intrusion detection:

1. Open a NEW terminal/command prompt
2. Navigate to this directory
3. Run: python honeyfile_trap.py monitor
4. In ANOTHER terminal, access a honeyfile:
   
   Windows:
   notepad honeyfiles\\passwords.txt
   type honeyfiles\\admin_config.txt
   
   Linux/macOS:
   cat honeyfiles/passwords.txt
   nano honeyfiles/admin_config.txt

5. Watch the monitoring terminal for alerts!
6. Press Ctrl+C to stop monitoring
7. View logs: python honeyfile_trap.py logs --type alert

🔍 Other useful commands:
- python honeyfile_trap.py report --days 1
- python honeyfile_trap.py export --type access --format csv
- python honeyfile_trap.py config --show
        """)
        
        print_step(6, "Quick Start Commands")
        print("""
# Start monitoring (run in separate terminal)
python honeyfile_trap.py monitor

# Generate more honeyfiles
python honeyfile_trap.py generate --count 15 --categories sensitive financial

# View recent alerts
python honeyfile_trap.py logs --type alert --limit 10

# Generate security report
python honeyfile_trap.py report --days 7 --output security_report.json

# Interactive configuration
python honeyfile_trap.py config --setup
        """)
        
        print_header("SETUP COMPLETE!")
        print("🎉 Honeyfile Trap is ready to use!")
        print("📖 See README.md and EXAMPLES.md for detailed documentation")
        print("🐛 Report issues at: https://github.com/yourusername/honeyfile-trap/issues")
        
        # Ask if user wants to start monitoring now
        try:
            start_now = input("\n🚀 Start monitoring now? (y/N): ").lower().startswith('y')
            if start_now:
                print("\n🔍 Starting monitoring... Press Ctrl+C to stop")
                print("💡 Tip: Access files in the 'honeyfiles' directory to trigger alerts")
                run_command("python honeyfile_trap.py monitor", capture=False)
        except KeyboardInterrupt:
            print("\n👋 Setup completed. Run 'python honeyfile_trap.py monitor' when ready!")
    
    except KeyboardInterrupt:
        print("\n\n🛑 Setup interrupted by user")
    except Exception as e:
        print(f"\n❌ Unexpected error during setup: {e}")
        print("Please check the error message above and try again")


if __name__ == "__main__":
    main()