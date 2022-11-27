import socket
from datetime import datetime
import sys
import scapy.all as scapy
import ipaddress

ports = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 43: "WHOIS", 53: "DNS", 80: "http",
    115: "SFTP", 123: "NTP", 143: "IMAP", 161: "SNMP",
    179: "BGP", 443: "HTTPS", 445: "MICROSOFT-DS",
    514: "SYSLOG", 515: "PRINTER", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN",
    1433: "SQL Server", 1723: "PPTP", 3128: "HTTP",
    3268: "LDAP", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 8080: "Tomcat", 10000: "Webmin"}


def get_port_service(tmp_port):
    try:
        return socket.getservbyport(tmp_port).upper()
    except OSError:
        return "UNKNOWN"


class PortStatus(object):
    OPEN = "Open"
    CLOSED = "Closed"
    FILTERED = "Filtered"


"""
host_name = sys.argv[1]
ip = socket.gethostbyname(host_name)

for port in ports:
    cont = socket.socket()
    cont.settimeout(1)
    try:
        cont.connect((ip, port))
    except socket.error:
        pass
    else:
        print(f"{socket.gethostbyname(ip)}:{str(port)} is open/{ports[port]}")
    cont.close()
ends = datetime.now()
print("<Time:{}>".format(ends))
input("Press Enter to the exit....")
"""


class PortScanFunc(object):

    def __init__(self, _ip):
        self.target_ip = _ip
        self.ports_banners = {}
        self.ports_services = {}
        self.closed_ports = {}

    def secret_port_scan(self, port):
        ip_request = scapy.IP(dst=self.target_ip)
        syn_request = scapy.TCP(dport=port, flags="S")
        syn_packet = ip_request / syn_request

        returned_answer = scapy.sr1(syn_packet, timeout=1, verbose=False)

        if returned_answer is not None:
            try:
                if returned_answer.getlayer(scapy.TCP).flags == "SA":

                    port_lib = {"port_status": PortStatus.OPEN, "port_number": port}
                    return port_lib

                elif returned_answer.getlayer(scapy.TCP).flags == "RA":

                    port_lib = {"port_status": PortStatus.CLOSED, "port_number": port}
                    return port_lib
            except AttributeError:
                port_lib = {"port_status": PortStatus.FILTERED, "port_number": port}

        port_lib = {"port_status": PortStatus.FILTERED, "port_number": port}
        return port_lib

    def ip_ports_scan(self, target_ports):
        if target_ports is None:
            target_ports += ports.keys()

        for port in target_ports:
            target_ports = PortScanFunc.secret_port_scan(self, port)
            if target_ports['port_status'] == "Open":
                host = self.target_ip
                port = target_ports['port_number']
                try:
                    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    soc.connect((host, port))
                    soc.settimeout(2)
                except TimeoutError:
                    continue
                try:
                    banner = soc.recv(1024).decode().strip()
                    if banner == "":
                        self.ports_services.update(
                            {target_ports['port_number']: get_port_service(target_ports['port_number'])})
                    else:
                        self.ports_banners.update({target_ports['port_number']: banner})
                except socket.timeout:
                    self.ports_services.update(
                        {target_ports['port_number']: get_port_service(target_ports['port_number'])})
                except UnicodeDecodeError:
                    try:
                        banner = soc.recv(1024)
                        if banner == "":
                            self.ports_services.update(
                                {target_ports['port_number']: get_port_service(target_ports['port_number'])})
                        else:
                            self.ports_banners.update({target_ports['port_number']: banner})
                    except socket.timeout:
                        self.ports_services.update(
                            {target_ports['port_number']: get_port_service(target_ports['port_number'])})

            if target_ports['port_status'] == "Closed":
                self.closed_ports.update({target_ports['port_number']: target_ports['port_status']})

    def port_status_print(self):

        for elem in self.ports_banners.keys():
            try:
                print(str(elem) + '/tcp' + '\t' * 2 + "  Open" + '\t' * 2 + str(get_port_service(elem)) + '\t'
                      + "Banner: " + self.ports_banners[elem])
            except TypeError:
                print(str(elem) + '/tcp' + '\t' * 2 + "  Open" + '\t' * 2 + str(get_port_service(elem)) + '\t'
                      + "Banner: ")
                print(self.ports_banners[elem])

        for elem in self.ports_services.keys():
            print(str(elem) + '/tcp' + '\t' * 2 + "  Open" + '\t' * 2 + "Service: " + self.ports_services[elem])

        for elem in self.closed_ports.keys():
            print(str(elem) + '/tcp' + '\t' * 2 + self.closed_ports[elem])

        print("\n")


default_ports = []
default_ports += ports.keys()

if __name__ == "__main__":
    text = open('banners_example.txt', 'w')
    set1 = ipaddress.ip_network('195.19.0.0/16')
    ip_list = [str(ip) for ip in set1]
    for ip in ip_list:
        print(ip)
        x = PortScanFunc(ip)
        x.ip_ports_scan(ports.keys())
        x.port_status_print()
        for elem in x.ports_banners:
            try:
                text.write(x.ports_banners[elem] + '\n')
            except TypeError:
                continue

        print("=======================")
    text.close()

    # ip = socket.gethostbyname('github.com')
