from flask import Flask, jsonify, render_template, request
from flask_cors import CORS
import threading
import time
import json
import os
import subprocess
from datetime import datetime

app = Flask(__name__)
CORS(app)  # Enable cross-origin requests

# Shared data storage
class NetworkState:
    def __init__(self):
        self.alerts = []
        self.arp_table = {}  # Current ARP table
        self.traffic_stats = []  # Traffic statistics
        self.packet_history = []  # Captured packet info
        self.attack_status = {"ongoing": False, "attacker": None, "target": None}
        
network_state = NetworkState()

# Home page / dashboard
@app.route('/')
def index():
    return render_template('dashboard.html')

# API endpoints
@app.route('/api/status')
def get_status():
    return jsonify({
        "alerts": network_state.alerts,
        "arp_table": network_state.arp_table,
        "traffic_stats": network_state.traffic_stats[-20:],  # Last 20 entries
        "attack_status": network_state.attack_status,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

@app.route('/api/alerts')
def get_alerts():
    return jsonify(network_state.alerts)

@app.route('/api/arp_table')
def get_arp_table():
    return jsonify(network_state.arp_table)

@app.route('/api/traffic')
def get_traffic():
    return jsonify(network_state.traffic_stats[-50:])  # Last 50 entries

@app.route('/api/packets')
def get_packets():
    return jsonify(network_state.packet_history[-100:])  # Last 100 packets

# Update endpoints (could be secured with authentication in production)
@app.route('/api/update_alert', methods=['POST'])
def update_alert():
    alert = request.json
    alert["id"] = len(network_state.alerts) + 1
    alert["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    network_state.alerts.append(alert)
    return jsonify({"status": "success", "alert_id": alert["id"]})

@app.route('/api/update_arp', methods=['POST'])
def update_arp():
    data = request.json
    ip = data.get("ip")
    mac = data.get("mac")
    if ip and mac:
        network_state.arp_table[ip] = {
            "mac": mac,
            "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "suspicious": data.get("suspicious", False)
        }
    return jsonify({"status": "success"})

@app.route('/api/set_attack_status', methods=['POST'])
def set_attack_status():
    network_state.attack_status = request.json
    return jsonify({"status": "success"})

# Background thread to simulate ARP table updates from sniffing
def update_arp_from_system():
    while True:
        try:
            # Execute the arp command and parse the results
            result = subprocess.run(['arp', '-a'], stdout=subprocess.PIPE)
            output = result.stdout.decode('utf-8')
            
            # Simple parsing of the arp command output
            for line in output.splitlines():
                if '(' in line and ')' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        ip = parts[1].replace('(', '').replace(')', '')
                        mac = parts[3]
                        if mac != '<incomplete>':
                            network_state.arp_table[ip] = {
                                "mac": mac,
                                "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "suspicious": False
                            }
        except Exception as e:
            print(f"Error updating ARP table: {e}")
            
        # Update traffic stats with dummy data
        network_state.traffic_stats.append({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "bytes_sent": len(network_state.arp_table) * 100,
            "bytes_received": len(network_state.arp_table) * 150
        })
        
        time.sleep(5)  # Update every 5 seconds

if __name__ == '__main__':
    # Start the background thread
    arp_thread = threading.Thread(target=update_arp_from_system)
    arp_thread.daemon = True
    arp_thread.start()
    
    # Create templates directory if needed
    os.makedirs('templates', exist_ok=True)
    
    # Run the Flask app
    app.run(host='0.0.0.0', port=8080, debug=True)
