import scapy.all as scapy #the tool thats like wireshark
import time
import os
from datetime import datetime

failed_logins = {}  #to record failed logis
blocked_ips = set()  # record blockIps (is used to prevent duplicate entries)

# Log detected threats to a file and print to the console
def log_threat(message, attack_type):
    log_entry = "[" + time.strftime("%Y-%m-%d %H:%M:%S") + "] " + message + " | Attack Type: " + attack_type
    with open("logs.txt", "a") as log_file:
        log_file.write(log_entry + "\n")
    print(log_entry)

# Block an IP using the system firewall
def block_ip(ip):
    if ip not in blocked_ips: 
        os.system("sudo iptables -A INPUT -s " + ip + " -j DROP") #uses iptables in firewall to block the IP
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

# Used to clear memory from old login attemps, so fresh information is shown (Code supported using DOcumentation)
def clean_expired_logins():
    current_time = datetime.now()
    for ip in list(failed_logins):
        if (current_time - failed_logins[ip]['last_attempt']).total_seconds() > 300:
            del failed_logins[ip]

# Reset iptables and clear old blocked IPs
def reset_firewall():
    print("Resetting firewall rules...")
    os.system("sudo iptables -F")  # Flush all iptables rules
    blocked_ips.clear()
    print("Firewall rules cleared.")

def detect_threat(packet):
    if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP): #if belonging to TCP IP

        #recording packet info in variables
        src_ip = packet[scapy.IP].src 
        dst_ip = packet[scapy.IP].dst
        dst_port = packet[scapy.TCP].dport
	
	    # Ignore packets from blocked IPs
        if src_ip in blocked_ips:
            return

        # printing live traffic
        print("[" + time.strftime("%Y-%m-%d %H:%M:%S") + "] " + src_ip + " -> " + dst_ip + ", Port: " + str(dst_port) + " | Attack Type: No")

        # Check if destination port was 22, to check for bruteforce attemps
        if dst_port == 22:
            clean_expired_logins() 

            # Track failed login attempts
            if src_ip not in failed_logins:
                failed_logins[src_ip] = {'count': 0, 'last_attempt': datetime.now()} #start count from 0
            failed_logins[src_ip]['count'] += 1                                      #the moment it is 2 times, it will block it
            failed_logins[src_ip]['last_attempt'] = datetime.now()

            # Log every failed login attempt
            log_threat(src_ip + " -> " + dst_ip + ", Port: " + str(dst_port), "Potential SSH Brute Force")

def start_sniffing(interface): 
    global failed_logins
    reset_firewall()  # Reset iptables rules and clear blocked IPs
    failed_logins = {}  # Reset failed logins when sniffing starts
    print("Starting packet sniffing on interface: " + interface)
    scapy.sniff(iface=interface, store=False, prn=detect_threat) #command to scappy to start sniffing on provided interface, prn is for callback if anything Other commands are taken from documentation

def show_blocked_ips():
    if blocked_ips:
        print("Blocked IPs:")
        for ip in blocked_ips:
            print(ip)
    else:
        print("No IPs are currently blocked.")

def view_logs():
    try:
        with open("logs.txt", "r") as log_file:
            for log in log_file:
                print(log.strip())
    except FileNotFoundError:
        print("No logs found.")

def show_menu():
    while True:

        print("--------------------------------------------------------------")
        print("""
         ___ ____  ____            ___ ___ _____
        |_ _|  _ \/ ___|          |_ _/ _ \_   _|
         | || | | \___ \   _____   | | | | || |
         | || |_| |___) | |_____|  | | |_| || |
        |___|____/|____/          |___\___/ |_|
        """)
        print("--------------------------------------------------------------")
        print("Network Intrusion Detection System Menu:")
        print("1. Start Packet Sniffing")
        print("2. Block an IP Manually")
        print("3. Remove IP from Blocklist")
        print("4. Show Blocked IPs")
        print("5. View Logs")
        print("6. Exit")
        print("--------------------------------------------------------------")

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

if __name__ == "__main__":
    show_menu()
