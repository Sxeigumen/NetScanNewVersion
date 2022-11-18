import scapy.all as scapy
import time
import socket
import json


class DnsStatus:
    successful_connection = "Successful connection"
    impossible_connection = "IP unavailable or Connection refused!"
    refused_connection = "Computer refused connection"


class DNSModule:
    def __init__(self, _ip):
        self.ip = _ip
        self.banner = ''
        self.status = ''
        self.host_name = ''

    def unitScan(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.ip, 53))
            host_name = socket.gethostbyaddr(self.ip)[0]
            self.host_name = host_name
            banner = sock.recv(1024).strip().decode()
            self.banner = banner
            sock.close()
            self.status = DnsStatus.successful_connection
        except TimeoutError:
            print(DnsStatus.impossible_connection)
            self.status = DnsStatus.impossible_connection
        except socket.timeout:
            print(DnsStatus.impossible_connection)
            self.status = DnsStatus.impossible_connection
        except ConnectionRefusedError:
            print(DnsStatus.refused_connection)
            self.status = DnsStatus.refused_connection

    def toJson(self):
        data_base = {}
        main_info = []
        ip = {f"Ip: {self.ip}"}
        status = {f"Status": self.status}
        banner = {f"Banner": self.banner}
        host_name = {f"Host Name": self.host_name}
        main_info.append(host_name)
        main_info.append(status)
        main_info.append(banner)
        data_base[f"{self.ip}"] = main_info
        with open("dns.json", "w") as file:
            json.dump(data_base, file, indent=3)


if __name__ == "__main__":
    a = DNSModule("192.168.50.1")
    a.unitScan()
    a.toJson()
