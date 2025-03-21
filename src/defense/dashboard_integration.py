import requests
import json
import time
import os
import sys

# Add project root to Python path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# URL of the dashboard API - Change this if needed
DASHBOARD_URL = "http://172.29.50.20:8080/api"

# Check if dashboard is available
def is_dashboard_available():
    try:
        response = requests.get(f"{DASHBOARD_URL}/status", timeout=0.5)
        return response.status_code == 200
    except:
        return False

# Send an alert to the dashboard
def send_alert_to_dashboard(alert):
    try:
        available = is_dashboard_available()
        print(f"[DEBUG] Dashboard available? {available}")
        if not available:
            print("[DEBUG] Dashboard not available, alert not sent")
            return False

        # Format the timestamp if it's a float/int
        if isinstance(alert.get('timestamp'), (float, int)):
            alert_copy = alert.copy()
            alert_copy['timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S',
                                            time.localtime(alert['timestamp']))
        else:
            alert_copy = alert

        print(f"[DEBUG] Sending alert to {DASHBOARD_URL}/update_alert: {alert_copy}")

        response = requests.post(
            f"{DASHBOARD_URL}/update_alert",
            json=alert_copy,
            headers={"Content-Type": "application/json"},
            timeout=2
        )
        print(f"[DEBUG] Dashboard response: {response.status_code}, {response.text}")
        return response.status_code == 200
    except Exception as e:
        print(f"[Dashboard] Error sending alert: {e}")
        import traceback
        traceback.print_exc()
        return False

# Update ARP table in the dashboard
def update_arp_table(ip, mac, suspicious=False):
    try:
        if not is_dashboard_available():
            return False

        data = {
            "ip": ip,
            "mac": mac,
            "suspicious": suspicious
        }

        response = requests.post(
            f"{DASHBOARD_URL}/update_arp",
            json=data,
            headers={"Content-Type": "application/json"},
            timeout=1
        )
        return response.status_code == 200
    except Exception as e:
        print(f"[Dashboard] Error updating ARP table: {e}")
        return False

# Update attack status in the dashboard
def set_attack_status(ongoing=False, attacker=None, target=None):
    try:
        if not is_dashboard_available():
            return False

        data = {
            "ongoing": ongoing,
            "attacker": attacker,
            "target": target
        }

        response = requests.post(
            f"{DASHBOARD_URL}/set_attack_status",
            json=data,
            headers={"Content-Type": "application/json"},
            timeout=1
        )
        return response.status_code == 200
    except Exception as e:
        print(f"[Dashboard] Error updating attack status: {e}")
        return False
