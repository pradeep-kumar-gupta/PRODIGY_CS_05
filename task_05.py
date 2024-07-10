from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

# Analyses the packet
def analyse_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        payload = packet[IP].payload
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # The protocol is determined.
        if protocol == 1:
            proto_name = "ICMP"
        elif protocol == 6:
            proto_name = "TCP"
        elif protocol == 17:
            proto_name = "UDP"
        else:
            proto_name = "Other"

        # Details of the packet are stored in packet_analysis
        packet_analysis = (
            f"Timestamp: {timestamp}\n"
            f"Source IP: {src_ip}\n"
            f"Destination IP: {dst_ip}\n"
            f"Protocol: {proto_name}\n"
            f"Payload: {payload}\n"
            f"\n{'-'*50}\n"
        )

        # Printing the Packet Analysis stored in packet_analysis
        print(packet_analysis)

def main():
    # Start sniffing packets
    print("Starting packet sniffer...\n\n")
    sniff(prn=analyse_packet, store=1)

if __name__ == "__main__":
    main()