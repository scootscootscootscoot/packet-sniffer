# Network Packet Sniffer

A Python script using Scapy to capture and analyze network packets on Ubuntu Linux.

## Features
- Captures source/destination IP, ports, and protocol (TCP/UDP/ICMP)
- Runs on specified network interface (e.g., eth0)
- Simple, timestamped output

## Prerequisites
- Ubuntu Linux
- Python 3
- Scapy (`pip install scapy`)

## Installation
1. Clone the repo: `git clone <your-repo-url>`
2. Navigate to the folder: `cd packet-sniffer`
3. Set up virtual environment: `python3 -m venv venv`
4. Activate it: `source venv/bin/activate`
5. Install dependencies: `pip install scapy`
6. Run the sniffer: `sudo venv/bin/python sniffer.py`

## Sample Output
[2025-02-27 15:42:10]
Source: 192.168.1.100:54321
Destination: 8.8.8.8:53
Protocol: UDP
