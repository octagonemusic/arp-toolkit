from scapy.all import sniff, srp, conf
from scapy.layers.l2 import ARP, Ether
import time
import subprocess
import threading
import sys

# Debug dashboard availability
print("[DEBUG] Looking for dashboard_integration module...")
try:
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
    # Define no-op functions when dashboard is not available
    def send_alert_to_dashboard(alert) -> bool:
        return False
    
    def update_arp_table(ip, mac, suspicious=False) -> bool:
        return False

def get_mac(ip, interface="eth0"):
    """Get MAC address for an IP using ARP request"""
    try:
        # Create ARP request
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        # Send the packet and get response
        result = srp(arp_request, timeout=3, verbose=0, iface=interface)[0]

        if result:
            # Return the MAC address from the response
            return result[0][1].hwsrc

        # Try alternative method using ARP table
        cmd = f"arp -n | grep {ip} | awk '{{print $3}}'"
        result = subprocess.check_output(cmd, shell=True).decode().strip()
        if result and result != "<incomplete>":
            return result
    except Exception as e:
        print(f"[ERROR] Failed to get MAC for {ip}: {e}")

    return None

class ARPWatchdog:
    def __init__(self, interface="eth0", target_gateway_ip=None):
        self.interface = interface
        conf.iface = interface  # Set scapy default interface

        self.ip_mac_mapping = {}  # Trusted IP->MAC mappings
        self.mac_history = {}     # History of all MACs seen for an IP
        self.alerts = []
        self.watching = False

        # Set specific gateway IP if provided, otherwise we'll learn from traffic
        self.target_gateway_ip = target_gateway_ip

        # If gateway IP is provided, try to get its MAC immediately
        if self.target_gateway_ip:
            print(f"[*] Target gateway specified: {self.target_gateway_ip}")
            print("[*] Actively probing for gateway MAC...")
            gateway_mac = get_mac(self.target_gateway_ip, interface)
            if gateway_mac:
                print(f"[+] Gateway MAC discovered: {gateway_mac}")
                self.add_trusted_mapping(self.target_gateway_ip, gateway_mac)
            else:
                print(f"[!] Could not get MAC for gateway {self.target_gateway_ip}")
                print("[!] Will learn it from traffic")

    def add_trusted_mapping(self, ip, mac):
        """Add a trusted IP-MAC mapping"""
        print(f"[+] Adding trusted mapping: {ip} -> {mac}")
        self.ip_mac_mapping[ip] = mac

        # Initialize MAC history
        if ip not in self.mac_history:
            self.mac_history[ip] = set()
        self.mac_history[ip].add(mac)

        # Update dashboard if available
        if DASHBOARD_AVAILABLE:
            update_arp_table(ip, mac)
            print(f"[DEBUG] Updated dashboard with trusted mapping: {ip} -> {mac}")

    def _create_alert(self, ip, original_mac, spoofed_mac):
        """Helper method to create and send alerts"""
        print(f"[CRITICAL] Creating alert for ARP spoofing on {ip}")
        print(f"[DETAILS] Original MAC: {original_mac}, Spoofed MAC: {spoofed_mac}")

        alert = {
            'timestamp': time.time(),
            'ip': ip,
            'original_mac': original_mac,
            'spoofed_mac': spoofed_mac,
            'message': f"ARP spoofing detected! {ip} has changed from {original_mac} to {spoofed_mac}"
        }

        # Add to local alerts list
        self.alerts.append(alert)
        print(f"[ALERT] {alert['message']}")

        # Send alert to dashboard if available
        if DASHBOARD_AVAILABLE:
            print(f"[DEBUG] Sending alert to dashboard for IP {ip}")
            result = send_alert_to_dashboard(alert)
            print(f"[DEBUG] Alert sent result: {result}")

            # Mark this IP-MAC mapping as suspicious in the dashboard
            update_arp_table(ip, spoofed_mac, suspicious=True)
            print(f"[DEBUG] Marked {ip}:{spoofed_mac} as suspicious in dashboard")

    def _check_arp_table(self):
        """Check system ARP table for any entries"""
        try:
            cmd = "arp -n"
            result = subprocess.check_output(cmd, shell=True).decode()

            print("[DEBUG] Current system ARP table:")
            print(result)

            # Parse ARP table output
            for line in result.strip().split('\n'):
                if not line.startswith('Address') and '(' not in line:  # Skip headers
                    parts = line.split()
                    if len(parts) >= 3:
                        ip = parts[0]
                        mac = parts[2]

                        if mac == '<incomplete>':
                            continue

                        # If this is our target gateway, record it
                        if self.target_gateway_ip and ip == self.target_gateway_ip:
                            if ip not in self.ip_mac_mapping:
                                print(f"[+] Found gateway MAC in ARP table: {mac}")
                                self.add_trusted_mapping(ip, mac)
                            elif self.ip_mac_mapping[ip] != mac:
                                print(f"[!] Gateway MAC in ARP table ({mac}) differs from our record ({self.ip_mac_mapping[ip]})")
                                self._create_alert(ip, self.ip_mac_mapping[ip], mac)

                        # Store all MAC addresses we see
                        if ip not in self.mac_history:
                            self.mac_history[ip] = set()
                        self.mac_history[ip].add(mac)

                        # Check for multiple MACs
                        if len(self.mac_history[ip]) > 1:
                            print(f"[WARNING] Multiple MACs for {ip} in history: {self.mac_history[ip]}")
                            if not any(alert['ip'] == ip for alert in self.alerts):
                                macs = list(self.mac_history[ip])
                                self._create_alert(ip, macs[0], macs[1])
        except Exception as e:
            print(f"[ERROR] Failed to check ARP table: {e}")

    def process_arp_packet(self, packet):
        """Process an ARP packet to detect spoofing"""
        if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP reply
            src_ip = packet[ARP].psrc
            src_mac = packet[ARP].hwsrc
            dst_ip = packet[ARP].pdst

            print(f"[DEBUG] Received ARP reply: {src_ip} is at {src_mac} (telling {dst_ip})")

            # Initialize MAC history for this IP if needed
            if src_ip not in self.mac_history:
                self.mac_history[src_ip] = set()

            # Add to MAC history
            self.mac_history[src_ip].add(src_mac)

            # Update dashboard immediately
            if DASHBOARD_AVAILABLE:
                # Mark as suspicious if we've seen multiple MACs for this IP
                suspicious = len(self.mac_history[src_ip]) > 1
                print(f"[DEBUG] Updating dashboard: {src_ip} -> {src_mac} (suspicious: {suspicious})")
                update_arp_table(src_ip, src_mac, suspicious=suspicious)

            # Special handling for target gateway IP
            if self.target_gateway_ip and src_ip == self.target_gateway_ip:
                print(f"[DEBUG] This is our target gateway IP: {src_ip}")

                # If we don't have a MAC for the gateway yet, learn it
                if src_ip not in self.ip_mac_mapping:
                    print(f"[+] Learning gateway MAC for the first time: {src_mac}")
                    self.add_trusted_mapping(src_ip, src_mac)
                # If the gateway MAC changed, this is highly suspicious
                elif self.ip_mac_mapping[src_ip] != src_mac:
                    print(f"[WARNING] Gateway MAC changed! Original: {self.ip_mac_mapping[src_ip]}, New: {src_mac}")
                    self._create_alert(src_ip, self.ip_mac_mapping[src_ip], src_mac)

            # General handling for all IPs
            elif src_ip in self.ip_mac_mapping:
                # If MAC is different from trusted mapping, it's suspicious
                if self.ip_mac_mapping[src_ip] != src_mac:
                    print(f"[WARNING] MAC changed for {src_ip}. Original: {self.ip_mac_mapping[src_ip]}, New: {src_mac}")
                    self._create_alert(src_ip, self.ip_mac_mapping[src_ip], src_mac)
            else:
                # First time seeing this IP, add to trusted mappings
                print(f"[INFO] Learning new IP-MAC from packet: {src_ip} -> {src_mac}")
                self.add_trusted_mapping(src_ip, src_mac)

            # Always check for multiple MACs - even if this is our first observation
            if len(self.mac_history[src_ip]) > 1:
                print(f"[WARNING] Multiple MACs observed for {src_ip}: {self.mac_history[src_ip]}")

                # Don't create duplicate alerts
                if not any(alert['ip'] == src_ip for alert in self.alerts):
                    macs = list(self.mac_history[src_ip])
                    self._create_alert(src_ip, macs[0], macs[1])

    def start_monitoring(self, timeout=None):
        """Start monitoring for ARP spoofing attacks"""
        self.watching = True
        print(f"[*] Starting ARP monitoring on {self.interface}")

        # Check ARP table first
        print("[*] Checking system ARP table...")
        self._check_arp_table()

        # Force an ARP request to the target gateway to get its MAC if we don't have it yet
        if self.target_gateway_ip and self.target_gateway_ip not in self.ip_mac_mapping:
            print(f"[*] Sending direct ARP request to target gateway {self.target_gateway_ip}...")

            # Create and send ARP request
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.target_gateway_ip)
            srp(arp_request, timeout=2, verbose=0, iface=self.interface)

            # Wait a moment for reply
            time.sleep(1)

            # Check if we got a response
            if self.target_gateway_ip in self.ip_mac_mapping:
                print(f"[+] Successfully learned gateway MAC: {self.ip_mac_mapping[self.target_gateway_ip]}")
            else:
                print("[!] Still couldn't get gateway MAC - will keep watching")

                # Make one more attempt with system ping to populate ARP table
                try:
                    print("[*] Pinging gateway to populate ARP table...")
                    subprocess.run(["ping", "-c", "1", self.target_gateway_ip],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    self._check_arp_table()  # Check ARP table again
                except:
                    pass

        # Start a background thread to periodically check the ARP table
        def background_checker():
            while self.watching:
                self._check_arp_table()
                time.sleep(5)  # Check every 5 seconds

        checker_thread = threading.Thread(target=background_checker)
        checker_thread.daemon = True
        checker_thread.start()

        try:
            print("[*] Starting packet capture...")
            sniff(
                filter="arp",
                prn=self.process_arp_packet,
                iface=self.interface,
                store=False,
                timeout=timeout
            )
        except KeyboardInterrupt:
            print("[*] ARP monitoring stopped by user")
        except Exception as e:
            print(f"[ERROR] Sniffing error: {e}")
        finally:
            self.watching = False
            print("[*] ARP monitoring stopped")

    def get_alerts(self):
        """Return all detected alerts"""
        return self.alerts
