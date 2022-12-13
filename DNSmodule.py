import scapy.all as scapy
import time
import socket
import json
import dns.resolver


# Класс содержит возможные статусы порта 53
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
        self.answer = ''

    # Функция сканирования порта 53
    def unitScan(self):
        try:
            # Создание INET и STREAM сокета
            # Эти константы представляют семейство адресов и протоколов
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            # Подключение к хосту по порту 53
            sock.connect((self.ip, 53))
            host_name = socket.gethostbyaddr(self.ip)[0]
            self.host_name = host_name
            banner = sock.recv(1024).strip().decode()
            self.banner = banner
            sock.close()
            self.status = DnsStatus.successful_connection
        except socket.gaierror:
            print(DnsStatus.impossible_connection)
            self.status = DnsStatus.impossible_connection
        except TimeoutError:
            print(DnsStatus.impossible_connection)
            self.status = DnsStatus.impossible_connection
        except socket.timeout:
            print(DnsStatus.impossible_connection)
            self.status = DnsStatus.impossible_connection
        except ConnectionRefusedError:
            print(DnsStatus.refused_connection)
            self.status = DnsStatus.refused_connection

    # Функция для отправки запросов на DNS сервер
    def getRequest(self):
        try:
            host_name = socket.gethostbyaddr(self.ip)[0]
        except socket.gaierror:
            print("No answer")
            return
        except socket.herror:
            print("No answer")
            return
        req = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
        for elem in req:
            try:
                answer = dns.resolver.resolve(host_name, elem)
            except dns.resolver.NoAnswer:
                print("No answer")
                continue
            except dns.resolver.LifetimeTimeout:
                print("No answer")
                continue
            print(answer.rrset)

    # Функция для создания отчёта о сканировании
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
    print("dns")
