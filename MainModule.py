import scapy.all as scapy
import argparse
import BasicScannerModule
import FtpModule
import NetworkScannerModule
import time
import json

parser = argparse.ArgumentParser(description='Scan and analyze network and ports.')

parser.add_argument('-network', type=bool, default=False, help='Scanning device ports with this IP.')
parser.add_argument('-cidr', type=str, default="/24", help='IPs range.')
parser.add_argument('-full_tcp', type=bool, default=False, help='Full TCP-scan.')

parser.add_argument('-ip', type=str, default=BasicScannerModule.local_ip(),
                    help='IP of this computer.')

parser.add_argument('-in_file', type=str, default=None, help='Print info about network in txt file.')

parser.add_argument('-port', type=int, help='Scan port')
parser.add_argument('-default_ports', type=bool, default=False, help='Ports scanning (default pool of ports)')
parser.add_argument('-ports_list', type=list, default=None, help='Info about your ports list.')

parser.add_argument('-anon_ftp', type=str, default=None, help='Anon FTP scan.')
parser.add_argument('-auth_ftp', type=str, default=None, help='Auth FTP scan.')
parser.add_argument('-login', type=str, default=None, help='Login fo auth.')
parser.add_argument('-password', type=str, default=None, help='Password fo auth.')

args = parser.parse_args()

working_network = BasicScannerModule.NetworkScanFunc()
working_network.scan_network(args.ip + args.cidr)
time.sleep(2)

if args.network:
    NetworkScannerModule.network_scan_func(working_network, args.in_file)


if args.port is not None:
    NetworkScannerModule.port_func(args.ip, args.port)


if args.default_ports:
    NetworkScannerModule.default_ports_func(args.ip)


if args.anon_ftp:
    target = FtpModule.ftpModule(args.anon_ftp)
    target.getFtpBanner()
    target.anonLogin()
    print(f"Banner: {target.banner}")

if args.auth_ftp:
    target = FtpModule.ftpModule(args.auth_ftp, args.login, args.password)
    target.getFtpBanner()
    target.authLogin()
    print(f"Banner: {target.banner}")


if args.full_tcp:
    NetworkScannerModule.full_tcp_func(working_network.network_base)
