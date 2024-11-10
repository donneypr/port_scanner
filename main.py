import socket

ports = [21, 22, 80, 443, 23, 25, 53, 110, 143, 445, 3389, 3306, 5432, 8080]
ip = '192.168.1.1'

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

print(f"Open ports on the specified ip {ip}: {scan_ports(ip, ports)}")
