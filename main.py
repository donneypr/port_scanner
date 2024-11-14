import socket
from scapy.all import IP, TCP, UDP, sr1
import threading

common_ports = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL", 
    3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Proxy"
}

def format_port_output(open_ports):
    formatted_ports = []
    for port in open_ports:
        service_name = common_ports.get(port, "Unknown")
        formatted_ports.append(f"\033[91m{port} ({service_name})\033[0m")
    return ", ".join(formatted_ports)

def tcp_connect_scan(ip, ports):
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
