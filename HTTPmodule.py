import scapy.all as scapy
import time
import socket
import json


# sock.sendall(b"GET / HTTP/1.1\r\nHost:" + self.ip.encode('UTF-8') + b"\r\nConnection: close\r\n\r\n")

class httpModule:

    def __init__(self, _ip=''):
        self.ip = _ip
        self.content = ''
        self.banner = ''
        self.status = ''
        self.massage = ''

    def unitScan(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.ip, 80))
            sock.sendall(b"GET / HTTP/1.1\r\nHost:" + self.ip.encode('UTF-8') + b"\r\n\r\n")
            self.content = sock.recv(4096).strip().decode()
            sock.close()
        except ConnectionRefusedError:
            print("Connection refused!")
        except TimeoutError:
            print("IP unavailable or Connection refused!")

    def getMassage(self):
        info = self.content.split('\r\n')   #поставил \r

        for elem in info:
            if "Server:" in elem:
                self.banner = elem

        for elem in info:
            if "HTTP" in elem:
                self.status = elem

    def toJson(self):
        data_base = {}
        main_info = []
        ip = {f"Ip: {self.ip}"}
        status = {f"Status:": self.status}
        banner = {f"Banner:": self.banner}
        main_info.append(status)
        main_info.append(banner)
        data_base[f"{self.ip}"] = main_info
        with open("http.json", "w") as file:
            json.dump(data_base, file, indent=3)


pp = httpModule("192.168.50.1")
pp.unitScan()
pp.getMassage()
pp.toJson()
