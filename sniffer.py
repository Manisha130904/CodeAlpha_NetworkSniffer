from scapy.all import sniff, IP, TCP, UDP

def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        if TCP in packet:
            proto_name = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            print(f"[TCP] {src_ip}:{sport} -> {dst_ip}:{dport}")
        elif UDP in packet:
            proto_name = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            print(f"[UDP] {src_ip}:{sport} -> {dst_ip}:{dport}")
        else:
            print(f"[OTHER] {src_ip} -> {dst_ip} (protocol {proto})")

print("Starting network sniffer... Press Ctrl+C to stop.\n")
sniff(prn=process_packet, store=False)