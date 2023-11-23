import scapy.all as scapy
import time
from datetime import datetime

def log_alert(alert):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("intrusion_log.txt", "a") as log_file:
        log_file.write(f"{timestamp} - {alert}\n")

def sniff_packets(interface, src_ip=None, dst_ip=None):
    scapy.sniff(iface=interface, store=False, prn=lambda x: process_packet(x, src_ip, dst_ip))

def process_packet(packet, src_ip, dst_ip):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        # Filter packets based on source and destination IP addresses
        if src_ip and ip_src != src_ip:
            return
        if dst_ip and ip_dst != dst_ip:
            return

        print(f"IP Source: {ip_src}, IP Destination: {ip_dst}, Protocol: {protocol}")

        if packet.haslayer(scapy.TCP):
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport
            print(f"TCP Source Port: {src_port}, TCP Destination Port: {dst_port}")

            # Display payload (first 100 characters) for TCP packets
            payload = str(packet[scapy.TCP].payload)[:100]
            print(f"TCP Payload: {payload}")

            # Intrusion detection logic for TCP packets
            if dst_port == 80:  # Example: Detecting traffic to HTTP (Port 80)
                alert = "Potential HTTP traffic detected."
                print(alert)
                log_alert(alert)

            elif dst_port == 443:  # Example: Detecting traffic to HTTPS (Port 443)
                alert = "Potential HTTPS traffic detected."
                print(alert)
                log_alert(alert)

            # Add more specific intrusion detection logic for TCP as needed

        elif packet.haslayer(scapy.UDP):
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport
            print(f"UDP Source Port: {src_port}, UDP Destination Port: {dst_port}")

            # Display payload (first 100 characters) for UDP packets
            payload = str(packet[scapy.UDP].payload)[:100]
            print(f"UDP Payload: {payload}")

            # Intrusion detection logic for UDP packets
            if dst_port == 53:  # Example: Detecting DNS traffic (Port 53)
                alert = "Potential DNS traffic detected."
                print(alert)
                log_alert(alert)

            elif dst_port == 123:  # Example: Detecting NTP traffic (Port 123)
                alert = "Potential NTP traffic detected."
                print(alert)
                log_alert(alert)

            # Add more specific intrusion detection logic for UDP as needed
            # For instance, you can add more conditions based on known attack patterns or specific UDP services

        # Add more conditions for other protocols as needed
        elif packet.haslayer(scapy.ICMP):
            alert = "Potential ICMP traffic detected."
            print(alert)
            log_alert(alert)
            # Add intrusion detection logic for ICMP as needed

        # Rate limiter to avoid overwhelming the console
        time.sleep(0.1)

if __name__ == "__main__":
    # Specify the network interface you want to monitor
    print("🍉 ⋆ 🍎  🎀  Ｗｅｌｃｏｍｅ░ｔｏ░ｔｈｅ░░Ｎｅｔｗｏｒｋ░ Intrusion Detection System ░ (NIDS) -----（RAHUL-Ｎｊ）　　）  🎀  🍎 ⋆ 🍉")
    default_interface = "eth0"
    network_interface = input(f"🍬👮  𝐄𝐍𝐓𝐄𝐑  🐺👮 THE  ▞▞▞ 🙂 𝗡𝗲𝘁𝘄𝗼𝗿𝗸 𝗜𝗻𝘁𝗲𝗿𝗳𝗮𝗰𝗲 🙂 ▞▞▞ (default is {default_interface}): ") or default_interface

    # Specify source and destination IP addresses for filtering (set to None to disable filtering)
    source_ip_filter = input("🍬👮  𝐄𝐍𝐓𝐄𝐑  🐺👮 THE 🙂 S𝐨𝐮𝐫𝐜𝐞 𝐈𝐏 A𝐝𝐝𝐫𝐞𝐬𝐬 🙂 to Filter (press Enter for no filter): ") or None
    destination_ip_filter = input("🍬👮  𝐄𝐍𝐓𝐄𝐑  🐺👮 THE 🙂 D𝐞𝐬𝐭𝐢𝐧𝐚𝐭𝐢𝐨𝐧 𝐈𝐏 A𝐝𝐝𝐫𝐞𝐬𝐬 🙂 to Filter (press Enter for no filter): ") or None

    sniff_packets(network_interface, src_ip=source_ip_filter, dst_ip=destination_ip_filter)
