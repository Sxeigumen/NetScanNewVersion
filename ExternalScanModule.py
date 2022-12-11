import socket
from datetime import datetime
import sys
import scapy.all as scapy
import ipaddress
import json

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


def ip_list_creator(ip_range):
    addrs = ipaddress.ip_network(ip_range)
    ip_list = [str(ip) for ip in addrs]
    return ip_list


class IpInfo(object):

    def __init__(self, _ip, _cidr):
        self.target_ip = _ip
        self.cidr = _cidr
        self.ips_list = ip_list_creator(_ip + '/' + _cidr)


class PortScanFunc(object):

    def __init__(self, _ip):
        self.target_ip = _ip
        self.ports_banners = {}
        self.ports_services = {}
        self.closed_ports = {}

    def port_scan(self, port):

        sock = socket.socket()
        sock.settimeout(1)
        try:
            sock.connect((self.target_ip, port))
        except socket.error:
            port_lib = {"port_status": PortStatus.CLOSED, "port_number": port}
            return port_lib
        sock.close()
        port_lib = {"port_status": PortStatus.OPEN, "port_number": port}
        return port_lib

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

    def console_print(self):
        print(self.target_ip)
        print(f"{'PORT':<10}  {'STATUS':<10}  {'INFO'}")
        for elem in self.ports_banners.keys():
            try:
                print(
                    f"{str(elem) + '/tcp':<10}  {'Open':<10}  {get_port_service(elem):<10}  Banner: {self.ports_banners[elem]}")
            except TypeError:
                print(f"{str(elem) + '/tcp':<10}  {'Open':<10}  {get_port_service(elem):<10}  Banner: ")
                print(self.ports_banners[elem])
        for elem in self.ports_services.keys():
            print(f"{str(elem) + '/tcp':<10}  {'Open':<10}  Service: {self.ports_services[elem]}")

        for elem in self.closed_ports.keys():
            print(f"{str(elem) + '/tcp':<10}  Close")

        print("\n")

    def only_meaningful_print(self):
        print("IP: " + self.target_ip + '\n')
        for elem in self.ports_banners.keys():
            try:
                print(
                    f"{str(elem) + '/tcp':<8}   Open  {get_port_service(elem):<8}   Banner: {self.ports_banners[elem]}")
            except TypeError:
                print(f"{str(elem) + '/tcp':<8}   Open  {get_port_service(elem):<8}   Banner: ")
                print(self.ports_banners[elem])


def inet_scanner_cidr(_ip, cidr, details_mode=False):
    data_base = {}
    ip_data = {}
    target = IpInfo(_ip, cidr)
    for ip in target.ips_list:
        single_ip_ports = []
        ports_data = {}

        scan_obj = PortScanFunc(ip)
        scan_obj.ip_ports_scan(ports.keys())
        scan_obj.console_print()

        for elem in scan_obj.ports_banners.keys():
            try:
                info = {"port_info": "Banner: " + scan_obj.ports_banners[elem], "danger_level": "High risk"}
            except TypeError:
                info = {"port_info": "Service: " + get_port_service(elem), "danger_level": "Medium risk"}
            port_info = {elem: info}
            single_ip_ports.append(port_info)

        for elem in scan_obj.ports_services.keys():
            info = {"port_info": "Service: " + scan_obj.ports_services[elem], "danger_level": "Medium risk"}
            port_info = {elem: info}
            single_ip_ports.append(port_info)

        if not details_mode:
            ports_data["ports"] = single_ip_ports

            if len(ports_data["ports"]) == 0:
                ip_data[ip] = "No open ports"
            else:
                ip_data[ip] = ports_data

        else:
            for elem in scan_obj.closed_ports.keys():
                info = {"danger_level": "low risk"}
                port_info = {elem: info}
                single_ip_ports.append(port_info)

            ports_data["ports"] = single_ip_ports
            ip_data[ip] = ports_data

    data_base["ip"] = ip_data
    with open("full_tcp.json", "w") as file:
        json.dump(data_base, file, indent=3)


def inet_scanner_list(ips_list, typer, details_mode=False):
    data_base = {}
    ip_data = {}
    for ip in ips_list:
        obj = ip
        if typer == 'domain':
            try:
                obj = socket.gethostbyname(ip)
            except socket.herror:
                continue
        single_ip_ports = []
        ports_data = {}

        scan_obj = PortScanFunc(obj)
        scan_obj.ip_ports_scan(ports.keys())
        scan_obj.console_print()

        for elem in scan_obj.ports_banners.keys():
            try:
                info = {"port_info": "Banner: " + scan_obj.ports_banners[elem], "danger_level": "High risk"}
            except TypeError:
                info = {"port_info": "Service: " + get_port_service(elem), "danger_level": "Medium risk"}
            port_info = {elem: info}
            single_ip_ports.append(port_info)

        for elem in scan_obj.ports_services.keys():
            info = {"port_info": "Service: " + scan_obj.ports_services[elem], "danger_level": "Medium risk"}
            port_info = {elem: info}
            single_ip_ports.append(port_info)

        if not details_mode:
            ports_data["ports"] = single_ip_ports

            if len(ports_data["ports"]) == 0:
                ip_data[obj] = "No open ports"
            else:
                ip_data[obj] = ports_data

        else:
            for elem in scan_obj.closed_ports.keys():
                info = {"danger_level": "low risk"}
                port_info = {elem: info}
                single_ip_ports.append(port_info)

            ports_data["ports"] = single_ip_ports
            ip_data[obj] = ports_data

    data_base["ip"] = ip_data
    with open("full_tcp.json", "w") as file:
        json.dump(data_base, file, indent=3)


default_ports = []
default_ports += ports.keys()

if __name__ == "__main__":
    ip = ["h247.net50.bmstu.ru", 'mt11.bmstu.ru', 'rk1.bmstu.ru']
    inet_scanner_list(ip, 'domain')
