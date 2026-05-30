from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Function to process each captured packet
def process_packet(packet):

    print("\n==============================")
    print("New Packet Captured")
    print("==============================")

    # Check if packet contains IP layer
    if packet.haslayer(IP):

        ip_layer = packet[IP]

        print(f"Source IP      : {ip_layer.src}")
        print(f"Destination IP : {ip_layer.dst}")
        print(f"Protocol Number: {ip_layer.proto}")

        # Identify Protocol
        if packet.haslayer(TCP):
            print("Protocol       : TCP")

        elif packet.haslayer(UDP):
            print("Protocol       : UDP")

        elif packet.haslayer(ICMP):
            print("Protocol       : ICMP")

        else:
            print("Protocol       : Other")

        # Display payload if available
        payload = bytes(packet.payload)

        if payload:
            print(f"Payload Data   : {payload[:50]}")

        print(f"Packet Length  : {len(packet)} bytes")

# Start sniffing packets
print("Starting Network Sniffer...")

sniff(prn=process_packet, store=False)
