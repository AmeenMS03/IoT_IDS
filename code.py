import scapy.all as scapy
import time
import os
from datetime import datetime

# Track failed SSH login attempts and blocked IPs
failed_logins = {}  # Tracks attempts per IP: {'IP': count}
blocked_ips = set()  # Tracks blocked IPs
FAILED_LOGIN_THRESHOLD = 5  # Number of failed attempts before blocking
FAILED_LOGIN_EXPIRY = 300  # Time in seconds before login attempts expire

# Log detected threats to a file and print to the console
def log_threat(message, attack_type):
    log_entry = "[" + time.strftime("%Y-%m-%d %H:%M:%S") + "] " + message + " | Attack Type: " + attack_type
    with open("logs.txt", "a") as log_file:
        log_file.write(log_entry + "\n")
    print(log_entry)

# Block an IP using the system firewall
def block_ip(ip):
    if ip not in blocked_ips:
        os.system("sudo iptables -A INPUT -s " + ip + " -j DROP")
        blocked_ips.add(ip)
        print("Blocked IP: " + ip)

# Unblock an IP
def unblock_ip(ip):
    if ip in blocked_ips:
        os.system("sudo iptables -D INPUT -s " + ip + " -j DROP")
        blocked_ips.remove(ip)
        print("Unblocked IP: " + ip)
    else:
        print("IP " + ip + " is not blocked.")

# Check if login attempts should expire
def clean_expired_logins():
    current_time = datetime.now()
    for ip in list(failed_logins):
        if (current_time - failed_logins[ip]['last_attempt']).total_seconds() > FAILED_LOGIN_EXPIRY:
            del failed_logins[ip]

# Detect brute force attacks and display live traffic
def detect_threat(packet):
    if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        dst_port = packet[scapy.TCP].dport
	
	# Ignore packets from blocked IPs
        if src_ip in blocked_ips:
            return

        # Display live traffic
        print("[" + time.strftime("%Y-%m-%d %H:%M:%S") + "] " + src_ip + " -> " + dst_ip + ", Port: " + str(dst_port) + " | Attack Type: No")

        # Check for SSH brute force on port 22
        if dst_port == 22:
            clean_expired_logins()  # Clean up old login attempts

            # Track failed login attempts
            if src_ip not in failed_logins:
                failed_logins[src_ip] = {'count': 0, 'last_attempt': datetime.now()}
            failed_logins[src_ip]['count'] += 1
            failed_logins[src_ip]['last_attempt'] = datetime.now()

            # If the threshold is exceeded, log and block the IP
            if failed_logins[src_ip]['count'] > FAILED_LOGIN_THRESHOLD:
                log_threat(src_ip + " -> " + dst_ip + ", Port: " + str(dst_port), "Brute Force - SSH - 22")
                block_ip(src_ip)

# Start packet sniffing on a specified interface
def start_sniffing(interface):
    global failed_logins
    failed_logins = {}  # Reset failed logins when sniffing starts
    print("Starting packet sniffing on interface: " + interface)
    scapy.sniff(iface=interface, store=False, prn=detect_threat)

# Show currently blocked IPs
def show_blocked_ips():
    if blocked_ips:
        print("Blocked IPs:")
        for ip in blocked_ips:
            print(ip)
    else:
        print("No IPs are currently blocked.")

# View logs from the file
def view_logs():
    try:
        with open("logs.txt", "r") as log_file:
            for log in log_file:
                print(log.strip())
    except FileNotFoundError:
        print("No logs found.")

# Main menu
def show_menu():
    while True:
        print("\n" + "-" * 50)
        print("Network Intrusion Detection System Menu:")
        print("1. Start Packet Sniffing")
        print("2. Block an IP Manually")
        print("3. Remove IP from Blocklist")
        print("4. Show Blocked IPs")
        print("5. View Logs")
        print("6. Exit")
        print("-" * 50)

        choice = input("Please select an option (1-6): ")

        if choice == "1":
            interface = input("Enter the network interface to monitor (e.g., eth0, wlan0): ")
            start_sniffing(interface)
        elif choice == "2":
            ip_to_block = input("Enter the IP address to block: ")
            block_ip(ip_to_block)
        elif choice == "3":
            ip_to_unblock = input("Enter the IP address to unblock: ")
            unblock_ip(ip_to_unblock)
        elif choice == "4":
            show_blocked_ips()
        elif choice == "5":
            view_logs()
        elif choice == "6":
            print("Exiting program.")
            break
        else:
            print("Invalid choice. Please select a valid option.")

# Run the program
if __name__ == "__main__":
    show_menu()
