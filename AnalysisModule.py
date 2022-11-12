import json

data_base = []
with open("full_tcp.json", "r") as file:
    temp_db = json.load(file)
    data_base = temp_db


high_risk = []
medium_risk = []
ips = data_base["ip"].keys()

for ip in ips:
    temp = data_base['ip'][ip]['ports']
    for port in temp:
        for elem in port:
            if port[elem]['danger_level'] == 'High risk':
                info = {ip: elem}
                high_risk.append(info)
            if port[elem]['danger_level'] == 'Medium risk':
                info = {ip: elem}                                           #port[elem]["port_info"]
                medium_risk.append(info)


