"""This is a network packet sniffer script."""
from scapy.all import sniff, Raw
from scapy.layers.inet import IP, TCP, UDP
def process_packet(packet):
    """
    Callback function triggered for every captured packet.
    Parses and displays key networking layers.
    """
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto_num = ip_layer.proto
        protocol = "UNKNOWN"
        if proto_num == 6:
            protocol = "TCP"
        elif proto_num == 17:
            protocol = "UDP"
        elif proto_num == 1:
            protocol = "ICMP"

        print(f"\n[+] New Packet: {src_ip} -> {dst_ip} | Protocol: {protocol}")

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print(f"    Ports: Src Port: {tcp_layer.sport} -> Dst Port: {tcp_layer.dport}")
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print(f"    Ports: Src Port: {udp_layer.sport} -> Dst Port: {udp_layer.dport}")

        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"    Payload (Raw Data): {payload[:100]}")


def main():
    """Start the packet sniffer and process captured packets."""
    print("="*60)
    print(" Starting Python Packet Sniffer... Press Ctrl+C to Stop.")
    print("="*60)
    sniff(prn=process_packet, store=0)

if __name__ == "__main__":
    main()
