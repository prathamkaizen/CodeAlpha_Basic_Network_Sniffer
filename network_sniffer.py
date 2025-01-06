from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from datetime import datetime

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        protocol = ip_layer.proto
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        packet_length = len(packet)

        # Get the current timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Determine the protocol
        protocol_name = ""
        if protocol == 1:
            protocol_name = "ICMP"
            if ICMP in packet:
                icmp_layer = packet[ICMP]
                icmp_type = icmp_layer.type
                icmp_code = icmp_layer.code
                print(f"ICMP Type: {icmp_type}, ICMP Code: {icmp_code}")
        elif protocol == 6:
            protocol_name = "TCP"
            if TCP in packet:
                tcp_layer = packet[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                print(f"Source Port: {src_port}, Destination Port: {dst_port}")
        elif protocol == 17:
            protocol_name = "UDP"
            if UDP in packet:
                udp_layer = packet[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
                print(f"Source Port: {src_port}, Destination Port: {dst_port}")
        else:
            protocol_name = "Unknown Protocol"

        # Print packet details
        print(f"Timestamp: {timestamp}")
        print(f"Protocol: {protocol_name}")
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Packet Length: {packet_length} bytes")
        print("-" * 50)

        # Save packet details to a file
        with open("packet_log.txt", "a") as file:
            file.write(f"Timestamp: {timestamp}\n")
            file.write(f"Protocol: {protocol_name}\n")
            file.write(f"Source IP: {src_ip}\n")
            file.write(f"Destination IP: {dst_ip}\n")
            file.write(f"Packet Length: {packet_length} bytes\n")
            file.write("-" * 50 + "\n")

def main():
    try:
        # Capture packets on the default network interface
        print("Starting packet capture...")
        sniff(prn=packet_callback, filter="ip", store=0)
    except Exception as e:
        print(f"Error during packet capture: {e}")

if __name__ == "__main__":
    main()
