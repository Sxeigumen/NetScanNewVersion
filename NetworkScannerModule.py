import scapy.all as scapy
import argparse
import BasicScannerModule
import FtpModule
import time
import json


def network_scan_func(_network, file_name=None):
    _network.print_network_scanning_information()
    if file_name is not None:
        ips = {"ips": _network.network_base}
        with open(file_name, 'w') as in_file:
            json.dump(ips, in_file, indent=3)


def port_func(_ip, _port):
    print("IP: " + _ip)
    targetIp = BasicScannerModule.PortScanFunc(_ip)
    targetIp.ip_ports_scan([_port])
    targetIp.port_status_print()


def default_ports_func(_ip):
    print("IP: " + _ip)
    default_ports_list = BasicScannerModule.default_ports
    targetIp = BasicScannerModule.PortScanFunc(_ip)
    targetIp.ip_ports_scan(default_ports_list)
    targetIp.port_status_print()


def full_tcp_func(_network):
    data_base = {}
    ip_data = {}
    print(_network)
    for ip in _network:
        print(ip["ip"])

        single_ip_ports = []
        ports_data = {}

        default_ports_list = BasicScannerModule.default_ports
        targetIp = BasicScannerModule.PortScanFunc(ip["ip"])
        targetIp.ip_ports_scan(default_ports_list)

        for elem in targetIp.ports_banners.keys():
            info = {"port_info": "Banner: " + targetIp.ports_banners[elem]}
            port_info = {elem: info}
            single_ip_ports.append(port_info)
            print(port_info)

        for elem in targetIp.ports_services.keys():
            info = {"port_info": "Service: " + targetIp.ports_services[elem]}
            port_info = {elem: info}
            single_ip_ports.append(port_info)
            print(port_info)

        ports_data["ports"] = single_ip_ports

        if len(ports_data["ports"]) == 0:
            ip_data[ip["ip"]] = "No open ports"
        else:
            ip_data[ip["ip"]] = ports_data

    data_base["ip"] = ip_data
    print(data_base)
    with open("full_tcp.json", "w") as file:
        json.dump(data_base, file, indent=3)
