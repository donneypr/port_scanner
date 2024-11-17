"""
Port Scanner Script
===================

This script performs different types of port scans on a specified IP address.
Available scan types:
1. TCP Connect Scan
2. SYN Scan (requires root privileges)
3. UDP Scan (requires root privileges)

The script uses the `socket` and `scapy` libraries for network scanning, identifying
open ports and their associated services.

Modules:
--------
- socket: For TCP connection-based scanning.
- scapy.all: For creating and sending raw packets during SYN and UDP scans.

Constants:
----------
- `common_ports`: Maps commonly used port numbers to service names.

Functions:
----------
1. `format_port_output(open_ports: list) -> str`:
    Formats open ports with their associated services in color-coded output.

2. `tcp_connect_scan(ip: str, ports: list) -> list`:
    Performs a TCP Connect Scan to identify open ports.

3. `syn_scan(ip: str, ports: list) -> list`:
    Performs a SYN Scan to identify open ports (requires root privileges).

4. `udp_scan(ip: str, ports: list) -> list`:
    Performs a UDP Scan to identify open ports (requires root privileges).

5. `scan_ports(ip: str, ports: list, scan_type: str) -> list`:
    Dispatches the appropriate scan method based on user selection.

Usage Example:
--------------
Run the script and input the target IP and scan type as prompted.

Dependencies:
-------------
- Python 3.x
- Scapy library: Install using `pip install scapy`.

Notes:
------
- Ensure you have permission to scan the target IP.
- SYN and UDP scans require root privileges.
"""

import socket
from scapy.all import IP, TCP, UDP, sr1
import threading

# Dictionary of commonly used ports and their services
common_ports = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL", 
    3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Proxy"
}

def format_port_output(open_ports):
    """
    Format a list of open ports with their service names.

    Parameters:
    - open_ports (list): List of open port numbers.

    Returns:
    - str: Formatted string of open ports with service names.
    """
    formatted_ports = []
    for port in open_ports:
        service_name = common_ports.get(port, "Unknown")
        formatted_ports.append(f"\033[91m{port} ({service_name})\033[0m")
    return ", ".join(formatted_ports)

def tcp_connect_scan(ip, ports):
    """
    Perform a TCP Connect Scan on the specified IP and ports.

    Parameters:
    - ip (str): Target IP address.
    - ports (list): List of ports to scan.

    Returns:
    - list: List of open ports.
    """
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def syn_scan(ip, ports):
    """
    Perform a SYN Scan on the specified IP and ports.

    Parameters:
    - ip (str): Target IP address.
    - ports (list): List of ports to scan.

    Returns:
    - list: List of open ports.
    """
    open_ports = []
    for port in ports:
        pkt = IP(dst=ip)/TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=1, verbose=0)
        if resp and resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:
            open_ports.append(port)
            # Send RST to close the connection
            sr1(IP(dst=ip)/TCP(dport=port, flags="R"), timeout=1, verbose=0)
    return open_ports

def udp_scan(ip, ports):
    """
    Perform a UDP Scan on the specified IP and ports.

    Parameters:
    - ip (str): Target IP address.
    - ports (list): List of ports to scan.

    Returns:
    - list: List of open ports.
    """
    open_ports = []
    for port in ports:
        pkt = IP(dst=ip)/UDP(dport=port)
        resp = sr1(pkt, timeout=1, verbose=0)
        if resp is None:
            open_ports.append(port)
        elif resp.haslayer(UDP):
            open_ports.append(port)
    return open_ports

def scan_ports(ip, ports, scan_type):
    """
    Perform a port scan based on the selected scan type.

    Parameters:
    - ip (str): Target IP address.
    - ports (list): List of ports to scan.
    - scan_type (str): Type of scan (1 for TCP, 2 for SYN, 3 for UDP).

    Returns:
    - list: List of open ports.
    """
    if scan_type == "1":
        print("Performing TCP Connect Scan...")
        return tcp_connect_scan(ip, ports)
    elif scan_type == "2":
        print("Performing SYN Scan...")
        return syn_scan(ip, ports)
    elif scan_type == "3":
        print("Performing UDP Scan...")
        return udp_scan(ip, ports)
    else:
        print("Invalid scan type selected.")
        return []

if __name__ == "__main__":
    ip = input("Enter the IP address you want to scan: ")
    print("Select the type of scan you want to perform:")
    print("1. TCP Connect Scan")
    print("2. SYN Scan (requires root privileges)")
    print("3. UDP Scan (requires root privileges)")
    scan_type = input("Enter the scan type (1, 2, or 3): ")

    open_ports = scan_ports(ip, common_ports.keys(), scan_type)
    if open_ports:
        print(f"Open ports on {ip}: {format_port_output(open_ports)}")
    else:
        print(f"No open ports found on {ip}.")
