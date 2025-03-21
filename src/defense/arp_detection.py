from scapy.all import ARP, sniff
import time
import os
import sys

# Debug dashboard availability
print("[DEBUG] Looking for dashboard_integration module...")
try:
    import sys
    print(f"[DEBUG] Python path: {sys.path}")
    from defense.dashboard_integration import send_alert_to_dashboard, update_arp_table
    DASHBOARD_AVAILABLE = True
    print("[+] Dashboard integration available")
    # Test connectivity
    from defense.dashboard_integration import is_dashboard_available
    if is_dashboard_available():
        print("[+] Successfully connected to dashboard API")
    else:
        print("[!] Could not connect to dashboard API")
except ImportError as e:
    DASHBOARD_AVAILABLE = False
    print(f"[-] Dashboard integration not available: {e}")

class ARPWatchdog:
    def __init__(self, interface="eth0"):
        self.interface = interface
        self.ip_mac_mapping = {}  # Stores known IP->MAC mappings
        self.alerts = []
        self.watching = False

    def add_trusted_mapping(self, ip, mac):
        """Add a trusted IP-MAC mapping"""
        self.ip_mac_mapping[ip] = mac
        print(f"Added trusted mapping: {ip} -> {mac}")

        # Update dashboard if available
        if DASHBOARD_AVAILABLE:
            update_arp_table(ip, mac)

    def process_arp_packet(self, packet):
        """Process an ARP packet to detect spoofing"""
        if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP reply
            src_ip = packet[ARP].psrc
            src_mac = packet[ARP].hwsrc

            # Update dashboard with ARP entry
            if DASHBOARD_AVAILABLE:
                print(f"[DEBUG] Updating ARP table: {src_ip} -> {src_mac}")
                update_arp_table(src_ip, src_mac)

            # Check if we have a record for this IP
            if src_ip in self.ip_mac_mapping:
                # If MAC is different, potential spoofing
                if self.ip_mac_mapping[src_ip] != src_mac:
                    # Create well-formatted alert
                    alert = {
                        'timestamp': time.time(),  # Keep as time.time() for local use
                        'ip': src_ip,
                        'original_mac': self.ip_mac_mapping[src_ip],
                        'spoofed_mac': src_mac,
                        'message': f"ARP spoofing detected! {src_ip} has changed from {self.ip_mac_mapping[src_ip]} to {src_mac}"
                    }

                    # Add to local alerts list
                    self.alerts.append(alert)
                    print(f"[ALERT] {alert['message']}")

                    # Send alert to dashboard if available - with more debugging
                    if DASHBOARD_AVAILABLE:
                        print(f"[DEBUG] Sending alert to dashboard for IP {src_ip}")
                        result = send_alert_to_dashboard(alert)
                        print(f"[DEBUG] Alert sent result: {result}")

                        # Also mark this IP-MAC mapping as suspicious in the dashboard
                        update_arp_table(src_ip, src_mac, suspicious=True)
            else:
                # First time seeing this IP, add to mappings
                self.ip_mac_mapping[src_ip] = src_mac
                print(f"Learned new mapping: {src_ip} -> {src_mac}")

    def start_monitoring(self, timeout=None):
        """Start monitoring for ARP spoofing attacks"""
        self.watching = True
        print(f"[*] Starting ARP monitoring on {self.interface}")
        try:
            sniff(
                filter="arp",
                prn=self.process_arp_packet,
                iface=self.interface,
                store=False,
                timeout=timeout
            )
        except KeyboardInterrupt:
            self.watching = False
            print("[*] ARP monitoring stopped")

    def get_alerts(self):
        """Return all detected alerts"""
        return self.alerts
