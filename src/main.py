import argparse
import sys
from attack.arp_spoof import arp_spoof_attack
from defense.arp_detection import ARPWatchdog
from common.network_utils import get_interface, get_interface_ip, get_interface_mac

def main():
    parser = argparse.ArgumentParser(description="ARP Spoofing Tool")

    # Create subparsers for attack and defense
    subparsers = parser.add_subparsers(dest="mode", help="Mode of operation")

    # Attack mode arguments
    attack_parser = subparsers.add_parser("attack", help="ARP spoofing attack mode")
    attack_parser.add_argument("--target", "-t", required=True, help="Target IP to attack")
    attack_parser.add_argument("--gateway", "-g", required=True, help="Gateway IP")
    attack_parser.add_argument("--interface", "-i", default=None, help="Network interface to use")
    attack_parser.add_argument("--duration", "-d", type=int, default=60, help="Duration of attack in seconds")

    # Defense mode arguments
    defense_parser = subparsers.add_parser("defense", help="ARP spoofing defense mode")
    defense_parser.add_argument("--interface", "-i", default=None, help="Network interface to monitor")
    defense_parser.add_argument("--trusted", "-t", nargs=2, action='append',
                              metavar=('IP', 'MAC'), help="Add trusted IP-MAC pair")
    defense_parser.add_argument("--duration", "-d", type=int, help="Duration to monitor in seconds")
    # Add gateway argument to defense mode - MOVED HERE BEFORE PARSING
    defense_parser.add_argument("--gateway", "-g", help="Target gateway IP to monitor")

    args = parser.parse_args()

    # Auto-detect interface if not specified
    if not hasattr(args, 'interface') or args.interface is None:
        args.interface = get_interface()
        print(f"[*] Using auto-detected interface: {args.interface}")

    if args.mode == "attack":
        print(f"[*] Starting ARP spoofing attack against {args.target} via {args.gateway}")
        print(f"[*] Using interface: {args.interface}")
        arp_spoof_attack(args.gateway, args.target, args.interface, args.duration)

    elif args.mode == "defense":
        # Now we can use args.gateway correctly
        watchdog = ARPWatchdog(args.interface, target_gateway_ip=args.gateway)

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

    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
