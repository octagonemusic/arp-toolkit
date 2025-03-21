#!/usr/bin/env python
import argparse
import sys
import time
import os
import subprocess
import traceback

# Add parent directory to Python path
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# Try importing Flask to check if it's available
FLASK_AVAILABLE = False
try:
    import flask
    FLASK_AVAILABLE = True
    print("[+] Flask is available - dashboard can be used")
except ImportError:
    print("[-] Flask is not installed - dashboard will not be available")
    print("    Install with: pip install flask flask-cors")

# Import attack and defense modules
try:
    # Direct imports when used inside the Docker container
    from attack.arp_spoof import arp_spoof_attack
    from defense.arp_detection import ARPWatchdog
    print("[+] ARP toolkit modules imported successfully")
except ImportError as e:
    # Try src.* format as fallback
    try:
        from src.attack.arp_spoof import arp_spoof_attack
        from src.defense.arp_detection import ARPWatchdog
        print("[+] ARP toolkit modules imported successfully")
    except ImportError as e2:
        print(f"[!] Error importing ARP toolkit modules: {e}")
        traceback.print_exc()
        sys.exit(1)

# Import network utilities with fallback
try:
    from src.common.network_utils import get_interface, get_interface_ip, get_interface_mac
except ImportError:
    print("[!] Error importing network utilities, using fallbacks")
    def get_interface(): return "eth0"
    def get_interface_ip(iface): return None
    def get_interface_mac(iface): return None

def start_dashboard_server():
    """Start the dashboard server in a separate process"""
    if not FLASK_AVAILABLE:
        print("[!] Cannot start dashboard: Flask is not installed")
        return None

    try:
        print("[*] Starting dashboard server...")

        # Use the same Python interpreter that's running this script
        python_executable = sys.executable
        dashboard_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard_api.py")

        print(f"[*] Using Python: {python_executable}")
        print(f"[*] Dashboard path: {dashboard_path}")

        if not os.path.exists(dashboard_path):
            print(f"[!] Dashboard script not found at: {dashboard_path}")
            return None

        # Start process with stdout/stderr redirected
        dashboard_process = subprocess.Popen(
            [python_executable, dashboard_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        # Wait a moment for the server to start
        time.sleep(2)

        if dashboard_process.poll() is None:
            print(f"[+] Dashboard server running at http://localhost:8080")
            return dashboard_process
        else:
            stderr = dashboard_process.stderr.read().decode('utf-8')
            stdout = dashboard_process.stdout.read().decode('utf-8')
            print(f"[!] Failed to start dashboard server:")
            print(f"STDERR: {stderr}")
            print(f"STDOUT: {stdout}")
            return None

    except Exception as e:
        print(f"[!] Error starting dashboard: {e}")
        traceback.print_exc()
        return None

def main():
    parser = argparse.ArgumentParser(description="ARP Spoofing Tool")

    # Create subparsers for different modes
    subparsers = parser.add_subparsers(dest="mode", help="Mode of operation")

    # Attack mode arguments
    attack_parser = subparsers.add_parser("attack", help="ARP spoofing attack mode")
    attack_parser.add_argument("--target", "-t", required=True, help="Target IP to attack")
    attack_parser.add_argument("--gateway", "-g", required=True, help="Gateway IP")
    attack_parser.add_argument("--interface", "-i", default=None, help="Network interface to use")
    attack_parser.add_argument("--duration", "-d", type=int, default=60, help="Duration of attack in seconds")
    attack_parser.add_argument("--dashboard", action="store_true", help="Enable dashboard visualization")

    # Defense mode arguments
    defense_parser = subparsers.add_parser("defense", help="ARP spoofing defense mode")
    defense_parser.add_argument("--interface", "-i", default=None, help="Network interface to monitor")
    defense_parser.add_argument("--trusted", "-t", nargs=2, action='append',
                              metavar=('IP', 'MAC'), help="Add trusted IP-MAC pair")
    defense_parser.add_argument("--duration", "-d", type=int, help="Duration to monitor in seconds")
    defense_parser.add_argument("--dashboard", action="store_true", help="Enable dashboard visualization")

    # Dashboard mode arguments
    dashboard_parser = subparsers.add_parser("dashboard", help="Start dashboard only")
    dashboard_parser.add_argument("--port", "-p", type=int, default=8080, help="Port for dashboard server")

    args = parser.parse_args()

    if not args.mode:
        parser.print_help()
        return

    # Auto-detect interface if not specified
    if hasattr(args, 'interface') and args.interface is None:
        args.interface = get_interface()
        print(f"[*] Using auto-detected interface: {args.interface}")

    # Handle dashboard server for all modes
    dashboard_process = None

    if (args.mode in ["attack", "defense"] and hasattr(args, 'dashboard') and args.dashboard) or args.mode == "dashboard":
        if not FLASK_AVAILABLE:
            print("[!] Dashboard requested but Flask is not installed")
            print("    Install with: pip install flask flask-cors")
            if args.mode == "dashboard":
                return  # Exit if dashboard-only mode
        else:
            dashboard_process = start_dashboard_server()

    # Dashboard-only mode
    if args.mode == "dashboard":
        if dashboard_process:
            print("[*] Dashboard server is running. Press Ctrl+C to stop.")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("[*] Stopping dashboard server...")
                dashboard_process.terminate()
        return

    # Execute mode-specific logic
    if args.mode == "attack":
        print(f"[*] Starting ARP spoofing attack against {args.target} via {args.gateway}")
        print(f"[*] Using interface: {args.interface}")
        try:
            arp_spoof_attack(args.gateway, args.target, args.interface, args.duration)
        except Exception as e:
            print(f"[!] Error during attack: {e}")
            traceback.print_exc()

    elif args.mode == "defense":
        try:
            watchdog = ARPWatchdog(args.interface)

            # Add trusted mappings if provided
            if args.trusted:
                for ip, mac in args.trusted:
                    watchdog.add_trusted_mapping(ip, mac)
            else:
                # If no trusted mappings provided, let's add our own interface
                my_ip = get_interface_ip(args.interface)
                my_mac = get_interface_mac(args.interface)
                if my_ip and my_mac:
                    watchdog.add_trusted_mapping(my_ip, my_mac)
                    print(f"[*] Added own interface as trusted: {my_ip} -> {my_mac}")

            # Start monitoring
            watchdog.start_monitoring(args.duration)

            # After monitoring ends or is interrupted, print summary
            alerts = watchdog.get_alerts()
            if alerts:
                print(f"\n[!] Detected {len(alerts)} potential ARP spoofing attempts:")
                for alert in alerts:
                    print(f"  - {alert['message']}")
            else:
                print("\n[✓] No ARP spoofing detected.")
        except Exception as e:
            print(f"[!] Error during defense mode: {e}")
            traceback.print_exc()

    # Clean up dashboard process if it was started
    if dashboard_process:
        print("[*] Stopping dashboard server...")
        dashboard_process.terminate()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Operation interrupted by user")
    except Exception as e:
        print(f"[!] Unhandled error: {e}")
        traceback.print_exc()
