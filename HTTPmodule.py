import scapy.all as scapy
import time
import socket
import http.client


class httpModule:

    def __init__(self, _ip):
        self.host_ip = _ip
        self.message = ''


try:
    connection = http.client.HTTPSConnection("192.168.50.56", 80)
    connection.request("GET", "/")
    response = connection.getresponse()
    print("Status: {} and reason: {}".format(response.status, response.reason))
    connection.close()
except ConnectionRefusedError:
    print("Connection failed")
