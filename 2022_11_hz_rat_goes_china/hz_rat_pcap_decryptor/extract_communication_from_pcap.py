# The parser is dirty and a result of a work in progress approach.
# Don't expect too much ;)

import argparse
from pathlib import Path
from pprint import pprint

import dpkt as dpkt
from dpkt.utils import inet_to_str
from parse_protocol import _client_init_a_random_number, _client_init_b_hardcoded_strings, \
    _client_init_c_unixtime, _get_pkg_id, PKG_MAPPER, INT_PKG

SYN = 2
ACK = 16
SYN_ACK = 18


def main(opts: argparse.ArgumentParser):
    if not opts.c2:
        print_ips(opts.file)
    else:
        print_server_communication(opts.file, opts.c2)


def print_ips(file):
    ips = set()
    for ts, pkt in dpkt.pcap.Reader(file.open("rb")):
        eth = dpkt.ethernet.Ethernet(pkt)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue
        ips.add(inet_to_str(eth.ip.src))
        ips.add(inet_to_str(eth.ip.dst))

    pprint(ips)


def print_server_communication(file, c2):
    protocol_state = 0
    for ts, pkt in dpkt.pcap.Reader(file.open("rb")):
        eth = dpkt.ethernet.Ethernet(pkt)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue

        ip = eth.data
        if ip.p != dpkt.ip.IP_PROTO_TCP:
            continue
        if eth.data.tcp.flags in [SYN, ACK, SYN_ACK]:
            continue

        src_ip = inet_to_str(eth.ip.src)
        dst_ip = inet_to_str(eth.ip.dst)

        if c2 in [src_ip, dst_ip]:
            if c2 == src_ip:
                client = dst_ip
                client_port = eth.data.tcp.dport
                c2 = src_ip
                c2_port = eth.data.tcp.sport
                direction = "<- "
            else:
                client = src_ip
                client_port = eth.data.tcp.sport
                c2 = dst_ip
                c2_port = eth.data.tcp.dport
                direction = " ->"

            data = eth.data.tcp.flags

            if eth.data.tcp.data and eth.data.tcp.flags == 24:
                data = eth.data.tcp.data
                was_parsed, data_parsed = _parse_protocol_data(protocol_state, data)
                if was_parsed:
                    data = f"[ID {data_parsed.id}] {data_parsed.payload.decode()}"
                else:
                    data = data_parsed
                protocol_state += 1

            print(f"{client}:{client_port} {direction} {c2}:{c2_port} : {data}")


def _client_init_b_hardcoded_strings_and_client_init_c_unixtime(data):
    hardcoded = _client_init_b_hardcoded_strings(data[:5])
    init_time = _client_init_c_unixtime(data[5:])
    x = hardcoded.payload.decode() + " || " + init_time.payload.decode()
    return INT_PKG(id="INIT_BC", raw_payload=x.encode())


def _default_communication_flow(data_bytes: bytearray):
    pkg_id = _get_pkg_id(data_bytes)
    pkg = PKG_MAPPER.get(pkg_id)(pkg_id, data_bytes)
    return pkg


def _parse_protocol_data(protocol_state, data):
    b_array = bytearray(data)
    protocol_state = "default" if protocol_state >= len(PROTOCOL_PARSER) - 1 else protocol_state
    fkt = PROTOCOL_PARSER.get(protocol_state)
    return True, fkt(b_array)


def print_ips(file):
    ips = set()
    for ts, pkt in dpkt.pcap.Reader(file.open("rb")):
        eth = dpkt.ethernet.Ethernet(pkt)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue
        ips.add(inet_to_str(eth.ip.src))
        ips.add(inet_to_str(eth.ip.dst))

    pprint(ips)


def parse_args() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument('--file', type=Path, required=True, help="")
    parser.add_argument('--c2', type=str, help="Given IP will identify communication stream")

    return parser.parse_args()


PROTOCOL_PARSER = {0: _client_init_a_random_number,
                   1: _client_init_b_hardcoded_strings_and_client_init_c_unixtime,
                   # 1: _client_init_b_hardcoded_strings,
                   # 2: _client_init_c_unixtime,
                   "default": _default_communication_flow}

if __name__ == '__main__':
    opts = parse_args()
    main(opts)
