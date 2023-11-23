# Network-Intrusion-Detection-System-NIDS-

Overview:
The Network Intrusion Detection System (NIDS) with Scapy is a Python script designed to monitor and analyze network traffic on a specified interface. Leveraging the Scapy library, the script provides a flexible and customizable solution for detecting potential security threats within a network.

Features:
1. Packet Sniffing:
Utilizes Scapy for real-time packet sniffing, allowing the capture and analysis of network packets.

2. Filtering Capabilities:
Users can specify the network interface to monitor, with default options including "eth0" and "wlan0."
Allows filtering of packets based on source and destination IP addresses, providing a targeted analysis.

3. Protocol Analysis:
Performs in-depth analysis of network packets, extracting key information such as source and destination IP addresses, protocol types, and port numbers.

4. Intrusion Detection Logic:
Implements basic intrusion detection logic for common protocols:
TCP:Detects potential HTTP traffic on Port 80.
Identifies potential HTTPS traffic on Port 443.
Users can extend the logic to include additional conditions for specific applications or services.
UDP:Recognizes potential DNS traffic on Port 53.
Identifies potential NTP traffic on Port 123.
Users can expand the detection logic for other UDP-based services or applications.
ICMP:Flags potential ICMP traffic, often associated with network diagnostics or control messages.

5. Alerting and Logging:
Generates alerts for detected threats, providing real-time notifications.
Logs alerts to an "intrusion_log.txt" file, including timestamps for each event. This log facilitates further analysis and auditing.

6. User Configuration:
Users can easily configure the network interface to monitor, providing flexibility for different network environments.
Optional filtering by source and destination IP addresses allows for a more focused analysis.

Use Cases:

1. Network Security Monitoring:
Deployed as part of a broader security infrastructure to monitor and analyze network traffic for potential threats.

2. Incident Response:
Used to investigate and respond to security incidents by providing detailed information about the nature of network traffic.

3. Anomaly Detection:
Serves as a foundation for developing more advanced anomaly detection systems by extending the intrusion detection logic.

4. Educational Purposes:
Valuable for educational purposes, allowing students and professionals to understand the basics of network packet analysis and intrusion detection.

Usage Instructions:

1. Network Configuration:
Users can specify the network interface to monitor. Default options include "eth0" and "wlan0."

2. Filtering:
Optionally, users can specify source and destination IP addresses for filtering, focusing on specific communication flows.

3. Intrusion Detection Customization:
Users can customize the intrusion detection logic within the script to align with specific security requirements or network characteristics.

4. Logging and Analysis:
Detected threats are logged to an "intrusion_log.txt" file, providing a record of security events for analysis and audit purposes.
