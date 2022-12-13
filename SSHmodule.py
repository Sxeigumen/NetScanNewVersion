import scapy.all as scapy
import time
import socket
import json


# Класс содержит возможные статусы порта 22
class sshStatus:
    successful_connection = "Successful connection"
    impossible_connection = "IP unavailable or Connection refused!"
    refused_connection = "Computer refused connection"


class SSHModule:
    def __init__(self, _ip):
        self.ip = _ip
        self.banner = ''
        self.status = ''

    # Функция для сканирования порта 22
    def unitScan(self):
        try:
            # Создание INET и STREAM сокета
            # Эти константы представляют семейство адресов и протоколов
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            # Подключение к хосту по порту 22
            sock.connect((self.ip, 22))
            banner = sock.recv(1024).strip().decode()
            self.banner = banner
            sock.close()
            self.status = sshStatus.successful_connection
        except TimeoutError:
            print(sshStatus.impossible_connection)
            self.status = sshStatus.impossible_connection
        except socket.timeout:
            print(sshStatus.impossible_connection)
            self.status = sshStatus.impossible_connection
        except ConnectionRefusedError:
            print(sshStatus.refused_connection)
            self.status = sshStatus.refused_connection

    # Функция для создания отчёта о сканировании
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
    print('SSH')
