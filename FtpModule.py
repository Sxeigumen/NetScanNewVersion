import scapy.all as scapy
import time
import socket
import ftplib as ftp


class ftpStatus:
    goo = ""


class ftpModule(object):

    def __init__(self, _ip, _login="anonymous", _pass="anonymous@", _custom_port=21):
        self.host_ip = _ip
        self.login = _login
        self.password = _pass
        self.port = _custom_port
        self.banner = ''
        self.anon = True

    def getFtpBanner(self):
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        soc.connect((self.host_ip, self.port))
        ban = soc.recv(1024).decode().strip()
        self.banner = ban

    def anonLogin(self):
        service = ftp.FTP(self.host_ip)
        try:
            service.login()
            self.anon = True
            print(f"HOST: {self.host_ip}")
            print(f"PORT: {self.port}/tcp")
            print("Anonymous FTP login")
            print("---------------------------------------------")
            service.dir()
            service.quit()

        except ftp.error_perm:
            self.anon = False
            service.quit()
            print("Anonymous login is not possible")
            return

    def authLogin(self):
        service = ftp.FTP(self.host_ip)
        try:
            service.login(self.login, self.password)
            print(f"HOST: {self.host_ip}")
            print(f"PORT: {self.port}/tcp")
            print("FTP login with authentication")
            print("---------------------------------------------")
            service.dir()
            service.quit()

        except ftp.error_perm:
            print("Incorrect login or password")
            service.quit()
            return


if __name__ == "__main__":
    """
    t = ftpModule("ftp.us.debian.org", 'ubu', 'ubu')
    t.anonLogin()
    t.getFtpBanner()
    print(t.banner)
    """
