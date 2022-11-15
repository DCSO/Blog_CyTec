#!/usr/bin/env python3
#
#   Author: DCSO CyTec
#   https://medium.com/@DCSO_CyTec
#
#   Scan for HZ Rat servers
#
#   Example:
#   $ python3 server_scanner.py
#   $ python3 server_scanner.py --ip 58.240.32.125 --ports 8081 --extract-commands


import argparse
import ipaddress
import socket
from typing import List

from parse_protocol import parse_communication_flow

CLIENT_1_OK = b'CBBBR'
CLIENT_0_SEND_FAKE_COMMAND_LINE_RESULT = b'BBBN\n\x0f\x10\x03\x0fw\x18\x11\r\x0eOH'
CLIENT_255_ERROR_CODE = b'\xbdBBBB'

RESPONSE_COMMAND_LINE = [CLIENT_1_OK, CLIENT_0_SEND_FAKE_COMMAND_LINE_RESULT]

HELLO_HANDSHAKE = [
    b'\xa8[\xc1\xff',  # random value
    b'@BBBF',  # hardcoded strings
    b'\xda\xc1V ',  # timestamp
]

MOST_COMMON_PORTS = [8081, 8089, 8080, 11111]
KNOWN_PORTS = MOST_COMMON_PORTS + [18081, 28081, 443, 53961, 6523, 7744, 80, 8079, 8090, 8877, 9000, 9002, 9009, 9090]

IPS_TO_SCAN = [
    ('36.112.11.14', 8081),
    ('114.247.91.205', 8081),
    ('114.251.223.84', 8081),
    ('106.120.215.202', 8089),
    ('111.198.172.129', 8089),
    ('60.3.88.11', 8081),
    ('61.144.203.171', 8081),
    ('222.85.157.82', 8081),
    ('114.113.238.84', 6523),
    ('61.130.180.110', 8081),
    ('101.114.114.114', 9002),
    ('218.76.15.13', 8081),
    ('88.1.46.128', 8081),
    ('88.1.46.214', 8081),
    ('58.240.32.125', 8081),
    ('58.49.84.64', 8081),
    ('58.49.84.67', 443),
    ('58.49.84.65', 80),
    ('218.22.14.11', 8081),
    ('114.113.238.83', 9000),
    ('221.195.106.200', 9090),
    ('19.129.255.45', 8081),
    ('168.63.1.206', 8081),
    ('220.248.250.19', 8081),
    ('124.193.100.170', 18081),
    ('218.22.14.11', 8081),
    ('116.54.125.202', 8081),
    ('202.107.201.3', 8081),
    ('124.207.115.69', 28081),
    ('116.6.102.21', 8081),
    ('116.6.102.24', 8081),
    ('115.236.55.14', 11111),
    ('124.239.137.136', 8081),
    ('183.196.0.25', 8081),
    ('145.0.231.36', 8081),
    ('145.0.20.133', 8081),
    ('116.6.102.21', 8081),
    ('61.178.243.162', 9009),
    ('59.37.29.163', 8081),
    ('106.52.119.45', 8081),
    ('183.196.83.220', 8081),
    ('107.175.172.101', 8081),
    ('185.185.185.56', 8081),
    ('202.100.20.88', 53961),
    ('124.193.100.170', 8079),
    ('106.120.215.202', 8089),
    ('111.198.172.129', 8089),
    ('202.100.229.104', 8081),
    ('88.1.46.128', 8081),
    ('88.1.46.214', 8081),
    ('58.240.32.125', 8081),
    ('115.236.55.14', 11111),
    ('183.6.106.176', 8877),
    ('183.6.50.76', 8081),
    ('115.236.55.14', 11111),
    ('47.93.253.22', 8081),
    ('129.9.99.60', 8081),
    ('220.168.209.150', 8081),
    ('124.250.18.111', 8080),
    ('123.60.8.91', 8081),
    ('219.238.141.242', 8081),
    ('113.125.92.32', 8081),
    ('116.236.40.57', 8081),
    ('114.113.238.83', 9000),
    ('221.195.106.200', 9090),
    ('221.195.106.200', 8081),
    ('106.120.215.202', 8089),
    ('111.198.172.129', 8089),
    ('114.113.238.83', 9000),
    ('221.195.106.200', 9090),
    ('221.195.106.200', 8081),
    ('114.113.238.84', 6523),
    ('114.251.223.84', 8081),
    ('116.6.102.21', 8081),
    ('124.250.18.111', 8080),
    ('218.22.14.11', 8081),
    ('220.248.250.19', 8081),
    ('113.125.92.32', 8081),
    ('114.113.238.83', 9000),
    ('221.195.106.200', 9090),
    ('221.195.106.200', 8081),
    ('219.238.141.242', 8081),
]


class HZRat_Scanner:
    def scan_ip(self, ip, port, extract_commands):
        connection_success = self._send_authentication(ip, port, extract_commands)
        status_string = "Online" if connection_success else "Offline"
        return status_string, ip, port

    @staticmethod
    def _send_authentication(ip, port, extract_commands):
        connection_status = False
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(1)

        try:
            sock.connect((str(ip), port))
            for payload in HELLO_HANDSHAKE:
                sock.send(payload)

            while data := sock.recv(2048):
                connection_status = True
                if not extract_commands:
                    break

                for msg in parse_communication_flow(data, None):
                    print(msg)

                for payload in RESPONSE_COMMAND_LINE:
                    sock.send(payload)
        except (ConnectionRefusedError, TypeError, socket.error):
            pass

        sock.close()
        return connection_status


def main(opts: argparse.ArgumentParser):
    ips = sorted(set(IPS_TO_SCAN))
    ports = [KNOWN_PORTS + opts.ports] if opts.known_ports else opts.ports

    if opts.ip:
        ips = _create_ip_list([opts.ip], ports)
    elif opts.ips:
        ips = _create_ip_list(opts.ips, ports)
    elif opts.ip_range:
        ips = _create_ip_list(opts.ip_range, ports)

    _scan_for_hz_rat(ips, opts.extract_commands)


def _scan_for_hz_rat(ips: List, extract_commands: bool):
    hzr_scanner = HZRat_Scanner()
    for (tmp_ip, tmp_port) in ips:
        result, ip, port = hzr_scanner.scan_ip(tmp_ip, tmp_port, extract_commands=extract_commands)
        color_code = _print_green if result == "Online" else _print_red
        print(f"{color_code(result)} {ip}:{port}")


def _create_ip_list(ip_list: list, ports: list):
    for ip in ip_list:
        for port in ports:
            yield ip, port


def _print_red(text: str):
    CRED = '\033[91m'
    CEND = '\033[0m'
    return f"{CRED}{text}{CEND}"


def _print_green(text: str):
    CRED = '\033[92m'
    CEND = '\033[0m'
    return f"{CRED}{text}{CEND}"


def parse_args() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument('--ip', type=ipaddress.ip_address, help="IP address to test for HZ Rat Server")
    parser.add_argument('--ips', type=ipaddress.ip_address, nargs="+",
                        help="List of IP address to test for HZ Rat Server")
    parser.add_argument('--ip-range', type=ipaddress.IPv4Network, help="IP range to scan for HZ Rat Server(slow)")
    parser.add_argument('--ports', nargs="+", default=MOST_COMMON_PORTS, type=int, help="List of Ports to check")
    parser.add_argument('--known-ports', action='store_true', help="Add known ports to scan")
    parser.add_argument('--extract-commands', action='store_true',
                        help="Extract as much as possible commands from server  - keep communication ongoing")

    return parser.parse_args()


if __name__ == '__main__':
    opts = parse_args()
    main(opts)
