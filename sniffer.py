from scapy.all import *
import time

def packet_callback(packet):
    """Process and display packet information"""
    try:
        # Check if the packet has an IP layer
        if IP in packet:
            src_ip = packet[IP].src    # Source IP
            dst_ip = packet[IP].dst    # Destination IP
            
            # Determine the protocol
            if TCP in packet:
                protocol = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                protocol = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            elif ICMP in packet:
                protocol = "ICMP"
                src_port = "N/A"
                dst_port = "N/A"
            else:
                protocol = "Other"
                src_port = "N/A"
                dst_port = "N/A"

            # Format and print the packet information
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{timestamp}]")
            print(f"Source: {src_ip}:{src_port}")
            print(f"Destination: {dst_ip}:{dst_port}")
            print(f"Protocol: {protocol}")
            print("-" * 50)

    except Exception as e:
        print(f"Error processing packet: {e}")

def start_sniffer(interface="eth0", count=10):
    """Start the packet sniffer"""
    print("Starting packet sniffer...")
    print(f"Capturing {count} packets on {interface}. Press Ctrl+C to stop early.")
    
    try:
        # Sniff packets
        sniff(iface=interface, 
              prn=packet_callback, 
              filter="ip", 
              count=count)
        
    except KeyboardInterrupt:
        print("\nSniffer stopped by user.")
    except Exception as e:
        print(f"Error starting sniffer: {e}")

if __name__ == "__main__":
    # Default interface set to 'eth0' (common on Ubuntu), adjust if needed
    interface = "wlp0s20f3"  # Replace with your interface (e.g., 'wlan0' for Wi-Fi)
    packet_count = 10   # Number of packets to capture
    
    start_sniffer(interface, packet_count)
