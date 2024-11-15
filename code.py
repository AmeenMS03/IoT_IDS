import scapy.all as scapy
import time
from collections import defaultdict
import os

# Global dictionaries to track packets, failed logins, etc.
packet_count = defaultdict(int)
failed_logins = defaultdict(int)

# Define attack thresholds
DDOS_THRESHOLD = 100  # Example threshold for DDoS detection (packets per second)
PORT_SCAN_THRESHOLD = 20  # Example threshold for number of ports scanned

# Function to log detected threats
def log_threat(message, attack_type="Unknown"):
    with open("logs.txt", "a") as log_file:
        log_entry = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Attack Detected: {attack_type} | {message}\n"
        log_file.write(log_entry)
        print(log_entry)  # Print to console for real-time monitoring

# Function to detect the type of attack
def detect_threat(packet):
    global packet_count, failed_logins, PORT_SCAN_THRESHOLD  # Ensure we can modify the global variable

    # Check if packet has an IP layer
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        packet_length = len(packet)  # Get packet length

        # [LIVE TRAFFIC] Added live traffic output
        print(f"[LIVE TRAFFIC] [{time.strftime('%Y-%m-%d %H:%M:%S')}] {src_ip} -> {dst_ip}, Length: {packet_length}")

        # Track packet counts per source IP (for DDoS detection)
        packet_count[src_ip] += 1

        # DDoS Detection: If we have more than a threshold number of packets from the same IP in 1 second
        if packet_count[src_ip] > DDOS_THRESHOLD:
            threat_message = f"{src_ip} -> {dst_ip}, Length: {packet_length} [DDOS-Attempt]"
            print(f"[LIVE TRAFFIC] [{time.strftime('%Y-%m-%d %H:%M:%S')}] {threat_message}")  # Live alert for DDoS
            log_threat(threat_message, "DDoS")
        
        # SSH Brute Force Detection: Multiple failed login attempts on port 22
        if packet.haslayer(scapy.TCP) and packet[scapy.TCP].dport == 22:  # SSH Port
            if packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == "R":  # RST flag indicates failed connection
                failed_logins[src_ip] += 1
                if failed_logins[src_ip] > 5:  # Threshold for failed attempts
                    threat_message = f"{src_ip} -> {dst_ip}, Port: {packet[scapy.TCP].dport} [SSH Brute Force]"
                    print(f"[LIVE TRAFFIC] [{time.strftime('%Y-%m-%d %H:%M:%S')}] {threat_message}")  # Live alert for brute force
                    log_threat(threat_message, "SSH Brute Force")

# Function to start sniffing packets
def start_sniffing(interface):
    print(f"Starting network packet sniffing on interface: {interface}")
    scapy.sniff(iface=interface, store=False, prn=detect_threat)

# Menu system to interact with the user
def show_menu():
    while True:
        print("\nNetwork Intrusion Detection System Menu:")
        print("1. Start Packet Sniffing")
        print("2. Block an IP")
        print("3. View Logs")
        print("4. Exit")

        choice = input("Please select an option (1-4): ")

        if choice == "1":
            interface = input("Enter the network interface to monitor (e.g., eth0, wlan0): ")
            start_sniffing(interface)
        elif choice == "2":
            ip_to_block = input("Enter the IP address to block: ")
            block_ip(ip_to_block)
        elif choice == "3":
            view_logs()
        elif choice == "4":
            exit_program()
        else:
            print("Invalid choice. Please select a valid option.")

# Function to block an IP
def block_ip(ip):
    os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
    print(f"Blocked IP: {ip}")

# Function to view logs
def view_logs():
    try:
        with open("logs.txt", "r") as log_file:
            logs = log_file.readlines()
            for log in logs:
                print(log.strip())
    except FileNotFoundError:
        print("No logs found.")

# Function to exit the program
def exit_program():
    print("Exiting program.")
    exit(0)

# Main execution
if __name__ == "__main__":
    show_menu()
