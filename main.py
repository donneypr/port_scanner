import socket

ports = [21, 22, 80, 443, 23, 25, 53, 110, 143, 445, 3389, 3306, 5432, 8080]
ip = input("Enter the IP address you want to scan: ")

def scan_ports(ip, ports):
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        #bruh  0 means the port is closed
        result = sock.connect_ex((ip, port))  
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports 

open_ports = scan_ports(ip,ports)

if open_ports:
    print(f"Open ports on the specified IP {ip}: ", end="")
    print("\033[91m" + ", ".join(map(str, open_ports)) + "\033[0m")
else:
    print(f"No open ports found on the specified IP {ip}.")