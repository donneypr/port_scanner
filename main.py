import socket

ports = [21, 22, 80, 443, 23, 25, 53, 110, 143, 445, 3389, 3306, 5432, 8080]
ip = '192.168.1.1'

def scan_ports(ip, ports):
    open_ports = []
    for port in ports:
        socket.socket(socket.AF_INET, socket.SOCK_stream)
        sock.settimeout(1)
        result = socket.connect_ex((ip,port))
        #bruh if the port not open it should return 0
        if result == 0:
            open_ports.append(port)
        sock.close()
        return open_ports
    
    




