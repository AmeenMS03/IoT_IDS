import scapy.all as scapy
import time
import os

# Track failed SSH login attempts and blocked IPs
failed_logins = {}
blocked_ips = set()

# Threshold for blocking an IP after too many failed login attempts
FAILED_LOGIN_THRESHOLD = 5

# Function to log detected threats to file and print to console
def log_threat(message, attack_type="Unknown"):
    log_entry = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message} | Attack Type: {attack_type}"
    with open("logs.txt", "a") as log_file:
        log_file.write(log_entry + "\n")
    print(log_entry)

# Function to block an IP by adding it to the system's firewall
def block_ip(ip):
    if ip not in blocked_ips:
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
        blocked_ips.add(ip)
        print(f"Blocked IP: {ip}")

# Function to unblock an IP
def unblock_ip(ip):
    if ip in blocked_ips:
        os.system(f"sudo iptables -D INPUT -s {ip} -j DROP")
        blocked_ips.remove(ip)
        print(f"Unblocked IP: {ip}")
    else:
        print(f"IP {ip} is not blocked.")

# Function to check each packet for SSH brute force attempts
def detect_threat(packet):
    if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP):
        src_ip = packet[scapy.IP].src
        dst_port = packet[scapy.TCP].dport

        if dst_port == 22:  # Check only SSH traffic on port 22
            if src_ip not in failed_logins:
                failed_logins[src_ip] = 0
            failed_logins[src_ip] += 1

            if failed_logins[src_ip] > FAILED_LOGIN_THRESHOLD:
                log_threat(f"{src_ip} -> Port: {dst_port}", "Brute Force - SSH - 22")
                block_ip(src_ip)
            else:
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {src_ip} -> Port: {dst_port} | Attack Type: No")

# Function to start monitoring network traffic on a specified interface
def start_sniffing(interface):
    print(f"Starting packet sniffing on interface: {interface}")
    scapy.sniff(iface=interface, store=False, prn=detect_threat)

# Function to show currently blocked IPs
def show_blocked_ips():
    if blocked_ips:
        print("Blocked IPs:")
        for ip in blocked_ips:
            print(ip)
    else:
        print("No IPs are currently blocked.")

# Function to view logs from the file
def view_logs():
    try:
        with open("logs.txt", "r") as log_file:
            for log in log_file:
                print(log.strip())
    except FileNotFoundError:
        print("No logs found.")

# Main menu to interact with the system
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
