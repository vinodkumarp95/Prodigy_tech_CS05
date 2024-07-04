from scapy.all import *


def packet_handler(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        print(f"IP Packet: {src_ip} -> {dst_ip} | Protocol: {proto}")

        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"TCP Segment: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"UDP Segment: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

        elif packet.haslayer(ICMP):
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code
            print(f"ICMP Packet: {src_ip} -> {dst_ip} | Type: {icmp_type} | Code: {icmp_code}")

        # Print packet summary
        print(packet.summary())
        print("")


def main():
    print("Starting Packet Sniffer...")

    # Sniff packets with a filter (optional, can be left empty)
    sniff(filter="", prn=packet_handler, store=0)


if __name__ == "__main__":
    main()
