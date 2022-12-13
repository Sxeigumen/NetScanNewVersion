import pprint
import scapy.all as scapy
import time
import socket
import json
import http.client
import ssl


# sock.sendall(b"GET / HTTP/1.1\r\nHost:" + self.ip.encode('UTF-8') + b"\r\nConnection: close\r\n\r\n")

# Класс содержит возможные статусы порта 80
class httpStatus:
    successful_connection = "Successful connection"
    impossible_connection = "IP unavailable or Connection refused!"
    refused_connection = "Computer refused connection"


class httpModule:

    def __init__(self, _ip=''):
        self.ip = _ip
        self.content = ''
        self.banner = ''
        self.status = ''
        self.massage = ''
        self.headers = []

    # Функция для сканирования порта 80
    def unitScan(self):
        try:
            # Создание INET и STREAM сокета
            # Эти константы представляют семейство адресов и протоколов
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15)
            # Подключение к хосту по порту 80
            sock.connect((self.ip, 80))
            # Отправляем сообщение на http сервер
            sock.sendall(b"GET / HTTP/1.1\r\nHost:" + self.ip.encode('UTF-8') + b"\r\n\r\n")
            self.content = sock.recv(1024).strip().decode()
            sock.close()
        except UnicodeDecodeError:
            self.content = f"Decode Error"
        except ConnectionRefusedError:
            print(httpStatus.refused_connection)
            self.status = httpStatus.refused_connection
        except TimeoutError:
            print(httpStatus.impossible_connection)
            self.status = httpStatus.impossible_connection
        except socket.timeout:
            print(httpStatus.impossible_connection)
            self.status = httpStatus.impossible_connection

    # Функция для получения сообщения с http сервера
    def getMassage(self):
        info = self.content.split('\r\n')

        for elem in info:
            if "Server:" in elem:
                self.banner = elem

        for elem in info:
            if "HTTP" in elem:
                self.status = elem

    # Функция для получения ответа на GET запрос
    def getHeaders(self):
        try:
            name = socket.gethostbyaddr(self.ip)[0]
            connection = http.client.HTTPSConnection(name)
            connection.request("GET", "/")
            response = connection.getresponse()
            headers = response.getheaders()
            self.headers = headers
        except socket.herror:
            print(httpStatus.impossible_connection)
        except ssl.SSLCertVerificationError:
            print(httpStatus.impossible_connection)
        except ConnectionRefusedError:
            print(httpStatus.impossible_connection)
        except socket.gaierror:
            print(httpStatus.impossible_connection)
        except TimeoutError:
            print(httpStatus.impossible_connection)

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
        with open("http.json", "w") as file:
            json.dump(data_base, file, indent=3)


if __name__ == "__main__":
    print('http')
