# ARP Toolkit

A comprehensive toolkit for demonstrating, detecting, and analyzing ARP spoofing attacks on local networks.

## Overview

ARP Toolkit provides a set of tools for both educational and defensive purposes related to ARP (Address Resolution Protocol) spoofing attacks. The toolkit includes:

- **Attack Module**: Demonstrate how ARP spoofing works in a controlled environment
- **Defense Module**: Monitor the network for ARP spoofing attempts and alert when detected
- **Dashboard**: Visualize network activity and ARP changes in real-time
- **Docker Environment**: A containerized setup for safely practicing attacks and defense

This toolkit is designed for educational purposes, security testing, and enhancing network security awareness.

## Installation

### Prerequisites

- Docker and Docker Compose
- A host machine capable of running Docker containers

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/octagonemusic/arp-toolkit.git
   cd arp-toolkit
   ```

2. Build and start the Docker environment:
   ```bash
   cd docker
   docker-compose up -d
   ```

3. Verify the containers are running:
   ```bash
   docker-compose ps
   ```

## Quick Start Guide with Docker

### Step 1: Start the Dashboard and Defense (on the Victim Container)

Open two separate terminals for the victim container:

**Terminal 1 - Start the dashboard:**
```bash
docker exec -it victim bash
python main_with_dashboard.py dashboard
```

The dashboard will be accessible at http://172.29.50.20:8080 from your host machine.

**Terminal 2 - Run the defense module:**
```bash
docker exec -it victim bash
python main.py defense --gateway 172.29.50.10
```

### Step 2: Launch the Attack (on the Attacker Container)

Open a terminal for the attacker container:
```bash
docker exec -it attacker bash
python main.py attack --target 172.29.50.20 --gateway 172.29.50.10 --duration 30
```

### Step 3: Monitor the Results

1. Watch the defense terminal for alerts
2. Observe the attack progress in the attacker terminal
3. View real-time network status on the dashboard in your browser

## Detailed Docker Environment Setup

The toolkit includes a Docker environment with three containers that simulate a typical network scenario:

- **Gateway (172.29.50.10)**: Acts as the network gateway
- **Victim (172.29.50.20)**: Runs the defense tools and dashboard
- **Attacker (172.29.50.30)**: Runs the attack tools

### Container Access

Open terminals for each container:

```bash
# Gateway terminal
docker exec -it gateway bash

# Victim terminal (for dashboard and defense)
docker exec -it victim bash

# Attacker terminal
docker exec -it attacker bash
```

## Detailed Usage Guide

### Dashboard Setup (Victim Container)

The dashboard provides visual monitoring of the network and attack detection:

```bash
# In the victim container
python main_with_dashboard.py dashboard
```

Access the dashboard at http://172.29.50.20:8080

### Defense Setup (Victim Container)

Run the defense module to monitor for ARP spoofing attacks:

```bash
# In another terminal for the victim container
python main.py defense --gateway 172.29.50.10
```

Options:
- `--gateway, -g`: The gateway IP to monitor specifically (required)
- `--interface, -i`: Network interface to monitor (defaults to eth0 in Docker)
- `--trusted, -t`: Add trusted IP-MAC pairs (optional)
- `--duration, -d`: Duration to monitor in seconds (optional, runs indefinitely by default)

### Attack Execution (Attacker Container)

Execute the ARP spoofing attack:

```bash
# In the attacker container
python main.py attack --target 172.29.50.20 --gateway 172.29.50.10 --duration 30
```

Options:
- `--target, -t`: The target IP to attack (victim's IP) (required)
- `--gateway, -g`: The gateway IP (required)
- `--interface, -i`: Network interface to use (defaults to eth0 in Docker)
- `--duration, -d`: Duration of attack in seconds (default: 60)

## Complete Demo Walkthrough

### Preparation

1. Make sure Docker and Docker Compose are installed
2. Clone the repository and build the containers:
   ```bash
   git clone https://github.com/yourusername/arp-toolkit.git
   cd arp-toolkit/docker
   docker-compose up -d
   ```

### Running the Demo

#### Step 1: Start the Dashboard
```bash
docker exec -it victim bash
python main_with_dashboard.py dashboard
```
Leave this terminal open and keep the dashboard running.

#### Step 2: Run the Defense Module
In a new terminal:
```bash
docker exec -it victim bash
python main.py defense --gateway 172.29.50.10
```
Leave this terminal open to observe defense alerts.

#### Step 3: Open the Dashboard in Browser
Navigate to http://172.29.50.20:8080 in your web browser.

#### Step 4: Execute the Attack
In a new terminal:
```bash
docker exec -it attacker bash
python main.py attack --target 172.29.50.20 --gateway 172.29.50.10 --duration 30
```

#### Step 5: Observe the Results
- Watch the defense terminal for alert messages
- See the attack progress in the attacker terminal
- Monitor the real-time changes in the dashboard

### Monitoring Network Traffic (Optional)

You can monitor network traffic in any container:
```bash
# In any container
tcpdump -i eth0 -n arp
```

## How ARP Spoofing Works

ARP spoofing is a type of attack where an attacker sends falsified ARP messages over a local network, resulting in the linking of an attacker's MAC address with the IP address of a legitimate device on the network.

1. **Normal ARP Process**:
   - When a device wants to communicate with another on the local network, it needs to know the MAC address associated with the target IP
   - It broadcasts an ARP request: "Who has IP x.x.x.x?"
   - The owner of that IP responds with its MAC address
   - The first device stores this mapping in its ARP table

2. **During an ARP Spoofing Attack**:
   - The attacker sends fake ARP responses
   - These responses associate the attacker's MAC address with the IP address of another device (such as the gateway)
   - Victim devices update their ARP tables with this incorrect information
   - Traffic meant for the legitimate device is sent to the attacker instead

## Detection Techniques

The defense module employs several detection methods:

1. **Passive Monitoring**: Sniffing network ARP traffic to identify inconsistencies
2. **Active Probing**: Directly querying devices to verify MAC addresses
3. **ARP Table Analysis**: Monitoring ARP table changes for suspicious patterns
4. **MAC History Tracking**: Maintaining history of MAC addresses seen for each IP

When an attack is detected, the toolkit will:
- Generate alerts with detailed information in the defense terminal
- Update the dashboard in real-time
- Log the suspicious activity

## Dashboard Features

The dashboard provides a visual representation of the network and ARP tables:

- **Network Map**: Shows the current network topology
- **ARP Table**: Displays all known IP-MAC mappings
- **Alerts Panel**: Shows detected ARP spoofing attempts
- **Traffic Monitor**: Visualizes network traffic statistics

## Docker Container Architecture

The Docker environment consists of three containers on an isolated network:

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Gateway   │     │    Victim   │     │   Attacker  │
│             │     │             │     │             │
│172.29.50.10 │◄───►│172.29.50.20 │◄───►│172.29.50.30 │
└─────────────┘     └─────────────┘     └─────────────┘
                          ▲
                          │
                          ▼
                  ┌───────────────┐
                  │ Host Browser  │
                  │ Dashboard UI  │
                  │ Port 8080     │
                  └───────────────┘
```

## Troubleshooting

### Dashboard Issues

- **Dashboard not accessible**:
  - Ensure the dashboard process is running in the victim container:
    ```bash
    docker exec -it victim ps aux | grep main_with_dashboard
    ```
  - Check port mappings:
    ```bash
    docker-compose ps
    ```
  - Make sure your browser can connect to 172.29.50.20:8080

### Defense Module Issues

- **No alerts during attacks**:
  - Ensure you specified the correct gateway IP (172.29.50.10)
  - Check that the defense module is running with proper arguments
  - Verify the defense module has NET_ADMIN and NET_RAW capabilities

### Attack Module Issues

- **Attack not working**:
  - Ensure the attacker container has NET_ADMIN capability
  - Verify the correct target and gateway IPs are specified
  - Check that IP forwarding is enabled in the attacker container

## Advanced Usage

### Running Both Defense and Dashboard in One Command

For convenience, you can run the defense module with dashboard integration:

```bash
docker exec -it victim bash
python main_with_dashboard.py defense --gateway 172.29.50.10 --dashboard
```

This starts both the defense module and the dashboard in a single command.

### Adding Trusted IP-MAC Pairs

To reduce false positives, add trusted IP-MAC mappings:

```bash
python main.py defense --gateway 172.29.50.10 --trusted 172.29.50.30 xx:xx:xx:xx:xx:xx
```

## Security Considerations

- **Always get proper authorization** before running attack simulations on real networks
- This Docker environment provides an isolated setup for safe experimentation
- Remember that ARP spoofing is illegal when performed on networks without explicit permission

## Disclaimer

This toolkit is provided for educational and legitimate security testing purposes only. Users are responsible for obtaining proper authorization before testing on any network infrastructure.

Never use ARP spoofing techniques on networks without explicit permission, as unauthorized interception of network traffic is illegal in most jurisdictions.
