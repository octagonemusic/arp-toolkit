import netifaces
import socket
import struct
import fcntl

def get_interface():
    """Find the primary network interface (non-loopback)"""
    interfaces = netifaces.interfaces()
    for iface in interfaces:
        if iface != 'lo':
            addresses = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addresses:
                return iface
    return 'eth0'  # Default fallback

def get_interface_ip(interface):
    """Get the IP address of an interface"""
    try:
        return netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
    except (ValueError, KeyError, IndexError):
        return None

def get_interface_mac(interface):
    """Get the MAC address of an interface"""
    try:
        return netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr']
    except (ValueError, KeyError, IndexError):
        return None

def get_default_gateway():
    """Get the default gateway IP address"""
    try:
        gateways = netifaces.gateways()
        return gateways['default'][netifaces.AF_INET][0]
    except (KeyError, IndexError):
        return None
