import scapy.all as scapy
import time
import socket
import json


class sshStatus:
    successful_connection = "Successful connection"
    impossible_connection = "IP unavailable or Connection refused!"
    refused_connection = "Computer refused connection"


class SSHModule:
    def __init__(self, _ip):
        self.ip = _ip
        self.banner = ''
        self.status = ''

    def unitScan(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.ip, 22))
            banner = sock.recv(1024).strip().decode()
            self.banner = banner
            sock.close()
            self.status = sshStatus.successful_connection
        except TimeoutError:
            print(sshStatus.impossible_connection)
            self.status = sshStatus.impossible_connection
        except ConnectionRefusedError:
            print(sshStatus.refused_connection)
            self.status = sshStatus.refused_connection

    def toJson(self):
        data_base = {}
        main_info = []
        ip = {f"Ip: {self.ip}"}
        status = {f"Status": self.status}
        banner = {f"Banner": self.banner}
        main_info.append(status)
        main_info.append(banner)
        data_base[f"{self.ip}"] = main_info
        with open("ssh.json", "w") as file:
            json.dump(data_base, file, indent=3)


if __name__ == "__main__":
    a = SSHModule("192.168.50.3")
    a.unitScan()
