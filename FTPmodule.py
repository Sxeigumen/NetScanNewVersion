import scapy.all as scapy
import time
import socket
import ftplib as ftp
import json


class ftpStatus:
    impossible_anon_connection = "Anonymous connection is not possible"
    incorrect_sign = "Incorrect login or password"
    successful_connection = "Successful connection"
    refused_connection = "Computer refused connection"


class ftpModule(object):

    def __init__(self, _ip, _login="anonymous", _pass="anonymous@", _custom_port=21):
        self.host_ip = _ip
        self.login = _login
        self.password = _pass
        self.port = _custom_port
        self.banner = ''
        self.status = ''
        self.anon = True

    def getFtpBanner(self):
        try:
            soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            soc.settimeout(15)
            soc.connect((self.host_ip, self.port))
            ban = soc.recv(1024).decode().strip()
            self.banner = ban
        except TimeoutError:
            print("Getting banner is not possible")
            self.banner = "Getting banner is not possible"
        except socket.timeout:
            print("Getting banner is not possible")
            self.banner = "Getting banner is not possible"
        except ConnectionRefusedError:
            print("Getting banner is not possible, computer refused connection")
            self.status = ftpStatus.refused_connection
            return

    def anonLogin(self):
        try:
            service = ftp.FTP(self.host_ip)
        except TimeoutError:
            print(ftpStatus.impossible_anon_connection)
            self.status = ftpStatus.impossible_anon_connection
            return
        except ConnectionRefusedError:
            print(ftpStatus.refused_connection)
            self.status = ftpStatus.refused_connection
            return

        try:
            service.login()
            self.anon = True
            service.dir()
            service.quit()
            self.status = ftpStatus.successful_connection

        except ftp.error_perm:
            self.anon = False
            service.quit()
            print(ftpStatus.impossible_anon_connection)
            self.status = ftpStatus.impossible_anon_connection

    def authLogin(self):
        try:
            service = ftp.FTP(self.host_ip)
        except TimeoutError:
            print(ftpStatus.incorrect_sign)
            self.status = ftpStatus.incorrect_sign
            return
        except ConnectionRefusedError:
            print(ftpStatus.refused_connection)
            self.status = ftpStatus.refused_connection
            return

        try:
            service.login(self.login, self.password)
            service.dir()
            service.quit()
            self.status = ftpStatus.successful_connection

        except ftp.error_perm:
            print(ftpStatus.incorrect_sign)
            service.quit()
            self.status = ftpStatus.incorrect_sign

    def toJson(self):
        data_base = {}
        main_info = []
        ip = {f"Host: {self.host_ip}"}
        status = {f"Status": self.status}
        banner = {f"Banner": self.banner}
        main_info.append(status)
        main_info.append(banner)
        data_base[f"{self.host_ip}"] = main_info
        with open("ftp.json", "w") as file:
            json.dump(data_base, file, indent=3)


if __name__ == "__main__":
    t = ftpModule("192.168.50.1")
    t.anonLogin()
    t.getFtpBanner()
    t.toJson()
