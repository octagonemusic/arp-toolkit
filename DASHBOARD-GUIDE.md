# ARP Toolkit Dashboard Guide

This guide will help you set up and use the real-time dashboard for the ARP Spoofing toolkit.

## Prerequisites

Install the required dependencies:

```bash
pip install -r requirements-dashboard.txt
```

## Ways to Use the Dashboard

### Option 1: Start the Dashboard Separately

```bash
# Start just the dashboard server
python src/main_with_dashboard.py dashboard
```

This will start the dashboard server on http://localhost:8080

### Option 2: Enable Dashboard with Attack or Defense

```bash
# Run attack with dashboard visualization
python src/main_with_dashboard.py attack --target 172.29.50.20 --gateway 172.29.50.10 --dashboard

# Run defense with dashboard visualization
python src/main_with_dashboard.py defense --dashboard
```

## Viewing the Dashboard

Once the dashboard is running, open a web browser and navigate to:
http://localhost:8080

**Note for Docker Users:** If running in Docker, you'll need to expose port 8080 in your Docker Compose file:

```yaml
services:
  victim:
    ports:
      - "8080:8080"
```

## Dashboard Features

1. **Network Map**: Visual representation of gateway, victim, and attacker
2. **ARP Table**: Real-time view of the ARP table with status indicators
3. **Traffic Monitor**: Graph showing network traffic during attacks
4. **Alerts Panel**: Real-time alerts for detected ARP spoofing attempts

## Troubleshooting

If the dashboard doesn't work:

1. Check that Flask is properly installed
2. Ensure port 8080 is not in use by another application
3. If using Docker, verify the port mapping is correct
4. Check the console for any error messages

## Technical Details

The dashboard consists of:

- Frontend: HTML/CSS/JavaScript using Bootstrap and Chart.js
- Backend: Flask API serving the dashboard and providing data endpoints
- Integration: Python modules that connect your ARP toolkit to the dashboard

The dashboard uses a RESTful API architecture with these endpoints:

- `/api/status`: Overall system status
- `/api/alerts`: ARP spoofing alerts
- `/api/arp_table`: Current ARP table entries
- `/api/traffic`: Network traffic statistics
