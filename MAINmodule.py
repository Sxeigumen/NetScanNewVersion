"""#!/usr/local/bin/python"""
import scapy.all as scapy
import argparse
import BasicScannerModule
import FTPmodule
import NetworkScannerModule
import time
import json

parser = argparse.ArgumentParser(description='Scan and analyze network.')

parser.add_argument('-network', type=bool, default=False, help='Scanning device\'s ports with this IP.')
parser.add_argument('-cidr', type=str, default="/24", help='IPs range (cidr).')
parser.add_argument('-full_tcp', type=bool, default=False, help='Full TCP-scan of network.')
parser.add_argument('-det_mode', type=bool, default=False, help='Output of complete information about the network.')
parser.add_argument('-work_mode', type=str, default=False, help='IP or domains use.')

parser.add_argument('-ip', type=str, default=BasicScannerModule.local_ip(), help='This computer IP.')

parser.add_argument('-port', type=int, help='Scan port')
parser.add_argument('-default_ports', type=bool, default=False, help='Ports scanning (default pool of ports)')

parser.add_argument('-anon_ftp', type=str, default=None, help='Anon FTP scan.')
parser.add_argument('-auth_ftp', type=str, default=None, help='Auth FTP scan (use with -login and -password.')
parser.add_argument('-login', type=str, default=None, help='Login for auth.')
parser.add_argument('-password', type=str, default=None, help='Password for auth.')

parser.add_argument('-http', type=str, default=None, help='HTTP scan.')

parser.add_argument('-dns', type=str, default=None, help='DNS scan.')

parser.add_argument('-inet_cidr', type=str, default=None, help='Scanning an external network (CIDR subnet).')
parser.add_argument('-inet_list', type=str, default=None, help='Scanning an external network (List of ip or domain).')

parser.add_argument('-analysis', type=bool, default=False, help='Scan analysis')

args = parser.parse_args()

working_network = BasicScannerModule.NetworkScanFunc()
working_network.scan_network(args.ip + args.cidr)
time.sleep(2)

if args.network:
    NetworkScannerModule.network_scan_func(working_network)

if args.port is not None:
    NetworkScannerModule.port_func(args.ip, args.port)

if args.default_ports:
    NetworkScannerModule.default_ports_func(args.ip)

if args.anon_ftp:
    NetworkScannerModule.anon_ftp(args.anon_ftp)

if args.auth_ftp:
    NetworkScannerModule.auth_ftp(args.auth_ftp, args.login, args.password)

if args.full_tcp:
    NetworkScannerModule.full_tcp_func(working_network.network_base, args.det_mode)

if args.http:
    NetworkScannerModule.http_scan(args.http)

if args.dns:
    NetworkScannerModule.dns(args.ip)

if args.inet_cidr:
    NetworkScannerModule.external_scan_cidr(args.ip, args.cidr, args.det_mode)

if args.inet_list:
    NetworkScannerModule.external_scan_list(args.work_mode, args.det_mode)

if args.analysis is True:
    NetworkScannerModule.basic_analyze()

