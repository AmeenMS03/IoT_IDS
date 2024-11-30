
# **Raspberry Pi Network Intrusion Detection System (NIDS)**

A Python-based Network Intrusion Detection System (NIDS) designed to detect and block malicious activities on a Raspberry Pi. This lightweight and efficient tool monitors live network traffic, detects malicious activity, and logs incidents for analysis.

<p align="center">
  <img src="https://github.com/user-attachments/assets/1a827374-d89f-4b3d-8f6a-2034264f732e" width="500">
</p>



## **Collaborators**
1. Ameen Siddiqui
2. [Mohammed Idris](https://github.com/mczdj) 

## **Features**
- **Brute Force Attack Detection**: Monitors SSH traffic for repeated failed login attempts and blocks offending IPs.
- **Live Traffic Monitoring**: Displays live network traffic with timestamps and identifies attack types.
- **Automatic IP Blocking**: Automatically blocks IPs that exceed a predefined failed login threshold.
- **Manual Block/Unblock**: Allows users to manually block or unblock IPs through a user-friendly menu.
- **Logs Management**: Logs all detected attacks with timestamps for future reference.
- **Menu-Driven Interface**: Simple and interactive CLI for ease of use.
- **Nmap Scan Detection**: Detects SYN, Null, and XMAS scans performed using tools like Nmap and logs them.
- **ARP Poisoning Detection**: Identifies ARP spoofing attempts to alert and log malicious behavior.

## **Installation**

### **Prerequisites**
- Raspberry Pi running a Linux-based OS.
- Python 3.x installed.
- Required Python modules: `scapy`.

### **Setup Instructions**
1. Clone this repository:
   ```
   git clone https://github.com/AmeenMS03/IoT_IDS.git
   cd IoT_IDS
   ```
2. Install the required Python library:
   ```
   sudo apt-get update
   sudo apt-get install python3-pip
   pip3 install scapy
   ```
3. Install `iptables` for IP blocking:
   ```
   sudo apt-get install iptables
   ```

## **Usage**

1. Run the program:
   ```
   sudo python3 code.py
   ```
2. Select an option from the menu:
   - **Start Packet Sniffing**: Monitors live traffic for potential brute force attacks, Nmap scans, and ARP poisoning attempts.
   - **Block an IP Manually**: Add an IP to the blocklist.
   - **Remove IP from Blocklist**: Unblock a previously blocked IP.
   - **Show Blocked IPs**: Display all currently blocked IPs.
   - **View Logs**: View recorded logs of detected attacks.
   - **Exit**: Quit the program.

## **Configuration**

- **Failed Login Threshold**:
  - Set the number of failed SSH login attempts before an IP is blocked.

- **Log File**:
  - All logs are saved in `logs.txt` in the same directory as the script.

## **Example Output**

### **Live Traffic**
```
[2024-11-15 12:00:00] 192.168.1.101 -> 192.168.1.24, Port: 22 | Attack Type: No
[2024-11-15 12:00:05] 192.168.1.101 -> 192.168.1.24, Port: 22 | Attack Type: Brute Force - SSH - 22
[2024-11-15 12:01:00] SYN scan detected from 192.168.1.102 to port 22 | Attack Type: Nmap SYN Scan
[2024-11-15 12:02:00] ARP Poisoning detected: 192.168.1.103 is claiming to be MAC 00:11:22:33:44:55
```

### **Blocked IPs**
```
Blocked IPs:
192.168.1.101
192.168.1.102
```

### **Logs**
```
[2024-11-15 12:00:05] 192.168.1.101 -> 192.168.1.24, Port: 22 | Attack Type: Brute Force - SSH - 22
[2024-11-15 12:01:00] SYN scan detected from 192.168.1.102 to port 22 | Attack Type: Nmap SYN Scan
[2024-11-15 12:02:00] ARP Poisoning detected: 192.168.1.103 is claiming to be MAC 00:11:22:33:44:55
```

## **License**

This project is licensed under the MIT License. See the `LICENSE` file for details.
