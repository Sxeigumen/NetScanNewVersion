import scapy.all as scapy
import time
import socket


def get_port_service(port):
    try:
        return socket.getservbyport(port).upper()
    except OSError:
        return "UNKNOWN"


def local_ip():
    ip = scapy.get_if_addr(scapy.conf.iface)
    time.sleep(5)
    return ip


class PortStatus(object):
    OPEN = "Open"
    CLOSED = "Closed"
    FILTERED = "Filtered"


class NetworkScanFunc(object):

    def __init__(self):
        self.ip = local_ip()
        self.network_base = []

    def scan_network(self, ips_range):
        arp_request = scapy.ARP(pdst=ips_range)
        broadcast_channel = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
        arp_packet = broadcast_channel / arp_request

        returned_answers = scapy.srp(arp_packet, verbose=False, timeout=1)[0]

        for elem in returned_answers:
            device = {"ip": elem[1].psrc, "mac": elem[1].hwsrc}
            self.network_base.append(device)

    def print_network_scanning_information(self):
        print("Ip-address\t\t\t\tMAC-address\n---------------------------------------------")
        for elem in self.network_base:
            print(elem["ip"] + "\t\t\t" + elem["mac"])
        print("---------------------------------------------")


class PortScanFunc(object):

    def __init__(self, _ip):
        self.target_ip = _ip
        self.ports_banners = {}
        self.ports_services = {}
        self.closed_ports = {}
    """
    def port_scan(self, port):
        ip_request = scapy.IP(dst=self.target_ip)
        syn_request = scapy.TCP(dport=port, flags="S")
        syn_packet = ip_request / syn_request

        returned_answer = scapy.sr1(syn_packet, timeout=1, verbose=False)

        if returned_answer is not None:

            if returned_answer.getlayer(scapy.TCP).flags == "SA":

                rst_request = scapy.TCP(dport=port, flags="AR")
                rst_packet = ip_request / rst_request

                send_rst = scapy.sr(rst_packet, timeout=1, verbose=False)

                port_lib = {"port_status": PortStatus.OPEN, "port_number": port}
                return port_lib

            else:
                port_lib = {"port_status": PortStatus.CLOSED, "port_number": port}
                return port_lib
    """
    def secret_port_scan(self, port):
        ip_request = scapy.IP(dst=self.target_ip)
        syn_request = scapy.TCP(dport=port, flags="S")
        syn_packet = ip_request / syn_request

        returned_answer = scapy.sr1(syn_packet, timeout=1, verbose=False)

        if returned_answer is not None:
            try:
                if returned_answer.getlayer(scapy.TCP).flags == "SA":
                    """
                    rst_request = scapy.TCP(dport=port, flags="R")
                    rst_packet = ip_request / rst_request
    
                    send_rst = scapy.sr(rst_packet, timeout=1, verbose=False)
                    """
                    port_lib = {"port_status": PortStatus.OPEN, "port_number": port}
                    return port_lib

                elif returned_answer.getlayer(scapy.TCP).flags == "RA":

                    port_lib = {"port_status": PortStatus.CLOSED, "port_number": port}
                    return port_lib
            except AttributeError:
                port_lib = {"port_status": PortStatus.FILTERED, "port_number": port}

        port_lib = {"port_status": PortStatus.FILTERED, "port_number": port}
        return port_lib

    def ip_ports_scan(self, target_ports):
        if target_ports is None:
            target_ports += ports_for_scanning.keys()

        for port in target_ports:
            target_ports = PortScanFunc.secret_port_scan(self, port)
            if target_ports['port_status'] == "Open":
                host = self.target_ip
                port = target_ports['port_number']
                try:
                    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    soc.connect((host, port))
                    soc.settimeout(2)
                except TimeoutError:
                    continue
                try:
                    banner = soc.recv(1024).decode().strip()
                    if banner == "":
                        self.ports_services.update(
                            {target_ports['port_number']: get_port_service(target_ports['port_number'])})
                    else:
                        self.ports_banners.update({target_ports['port_number']: banner})
                except socket.timeout:
                    self.ports_services.update(
                        {target_ports['port_number']: get_port_service(target_ports['port_number'])})

                except UnicodeDecodeError:
                    try:
                        banner = soc.recv(1024)
                        if banner == "":
                            self.ports_services.update(
                                {target_ports['port_number']: get_port_service(target_ports['port_number'])})
                        else:
                            self.ports_banners.update({target_ports['port_number']: banner})
                    except socket.timeout:
                        self.ports_services.update(
                            {target_ports['port_number']: get_port_service(target_ports['port_number'])})

            if target_ports['port_status'] == "Closed":
                self.closed_ports.update({target_ports['port_number']: target_ports['port_status']})

    def port_status_print(self):

        for elem in self.ports_banners.keys():
            try:
                print(
                    str(elem) + '/tcp' + '\t' * 2 + "  Open" + '\t' * 2 + str(get_port_service(elem)) + '\t' + "Banner: " +
                    self.ports_banners[elem])
            except TypeError:
                print(str(elem) + '/tcp' + '\t' * 2 + "  Open" + '\t' * 2 + str(get_port_service(elem)) + '\t'
                      + "Banner: ")
                print(self.ports_banners[elem])

        for elem in self.ports_services.keys():
            print(str(elem) + '/tcp' + '\t' * 2 + "  Open" + '\t' * 2 + "Service: " + self.ports_services[elem])

        for elem in self.closed_ports.keys():
            print(str(elem) + '/tcp' + '\t' * 2 + self.closed_ports[elem])

        print("\n")


ports_for_scanning = {20: 'FTP', 21: 'FTP Control', 22: 'SSH',
                      23: 'Telnet', 25: 'SMPT', 53: 'DNS',
                      67: 'DHCP Server', 68: 'DHCP Client',
                      69: 'TFTP', 80: 'HTTP', 110: 'POP3',
                      119: 'NNTP', 139: 'NetBIOS', 143: 'IMAP',
                      389: 'LDAP', 443: 'HTTPS', 445: 'SMB',
                      465: 'SMTP', 569: 'MSN', 587: 'SMTP',
                      990: 'FTPS', 993: 'IMAP', 995: 'POP3'}
default_ports = []
default_ports += ports_for_scanning.keys()

if __name__ == "__main__":
    """
    PortScanFunc.get_banners("192.168.50.1", 21)
    target = PortScanFunc("192.168.50.1")
    target.ip_ports_scan(default_ports)
    target.port_status_print()
    """