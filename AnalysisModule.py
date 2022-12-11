import json
import NetworkScannerModule


class Analysis:

    def __init__(self):
        self.data_base = []
        self.high_risk = []
        self.medium_risk = []
        self.ips = []

    def fileInit(self):
        with open("full_tcp.json", "r") as file:
            temp_db = json.load(file)
            self.data_base = temp_db
        self.ips = self.data_base["ip"].keys()
        for ip in self.ips:
            try:
                temp = self.data_base['ip'][ip]['ports']
                for port in temp:
                    for elem in port:
                        if port[elem]['danger_level'] == 'High risk':
                            info = {elem: ip}
                            self.high_risk.append(info)
                        if port[elem]['danger_level'] == 'Medium risk':
                            info = {elem: ip}  # port[elem]["port_info"]
                            self.medium_risk.append(info)
            except TypeError:
                continue

    def checkAll(self):
        for elem in self.medium_risk:
            a = []
            a += elem.keys()
            if a[0] == '21':
                print(f"Port: {a[0]}   IP: {elem[a[0]]}")
                print('==================================')
                NetworkScannerModule.anon_ftp(elem[a[0]])
                print('==================================')
            if a[0] == '80':
                print(f"Port: {a[0]}   IP: {elem[a[0]]}")
                print('==================================')
                NetworkScannerModule.http_scan(elem[a[0]])
                print('==================================')
            if a[0] != '1':
                print(f"Port: {53}   IP: {elem[a[0]]}")
                print('==================================')
                NetworkScannerModule.dns(elem[a[0]])
                print('==================================')
            print()


if __name__ == "__main__":
    A = Analysis()
    A.fileInit()
    A.checkAll()