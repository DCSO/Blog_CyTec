#!/usr/bin/env python3
#
#   Author: DCSO CyTec
#   https://medium.com/@DCSO_CyTec
#
#   Extract ips from HZ Rat samples
#
#   Example:
#   $ python3 hz_rat_cnc_extractor.py --files efbb9ad80a2c340d78816f11ea5192b771ac3b5a966a8aa5f7d5bd54d7453bad.exe


import argparse
import hashlib
import json
import struct
from argparse import Namespace
from pathlib import Path
from pprint import pprint
from typing import List

import pefile


class HZRatExtractor:
    def __init__(self, sample_file: Path):
        self.sample_file = sample_file
        self.data = self.sample_file.read_bytes()

        self.IDENTIFIER = {
            "HZ_2.9.1": (b"Release\\Default.pdb", self._extract_cnc_291),
            "HZ_2.9.0": (b"HZ_2.9.0\\Trojan", self._extract_cnc_282),
            "HZ_2.8.2": (b"HZ_2.8.2\\hp_client_win", self._extract_cnc_290),
        }

    def extract_cnc(self):
        if not self.data.startswith(b"MZ"):
            return

        for key, (pattern, fkt) in self.IDENTIFIER.items():
            if self.data.find(pattern):
                return fkt(self.sample_file, self.data)
        self.handle_error(self.sample_file, self.data, "Unknown version")

    def _extract_cnc_291(self, sample_data, data):
        pe = pefile.PE(sample_data)
        img_base = pe.OPTIONAL_HEADER.ImageBase
        img_size = pe.OPTIONAL_HEADER.SizeOfImage
        for i in range(len(data)):
            if data[i] == 0xBF and data[i + 4] == 0:

                possible_va = struct.unpack_from("<I", data[i + 1:])[0]

                if not (img_base < possible_va < img_base + img_size):
                    continue

                possible_rva = possible_va - img_base
                sect = pe.get_section_by_rva(possible_rva)
                if not sect.Name.startswith(b".rdata"):
                    continue

                ip_list = self._dump_ip_list(pe, possible_rva)
                return self._success(sample_data, data, "2.9.1", ip_list)
        return self.handle_error(sample_data, data, "IP list not found")

    def _extract_cnc_290(self, sample_data, data):
        pe = pefile.PE(sample_data)

        # all samples use the same offset
        rva = 0x4E800
        ip_list = self._dump_ip_list(pe, rva)
        return self._success(sample_data, data, "2.9.0", ip_list)

    def _extract_cnc_282(self, sample_data, data):
        ret = self._extract_cnc_290(sample_data, data)
        ret["version"] = "2.8.2"
        return ret

    def _success(self, sample_file: Path, data: bytearray, ver: str, ip_list: List):
        return {
            "file": str(sample_file.name),
            "status": "success",
            "cncs": ip_list,
            "hash": self.sha256(data),
            "version": ver,
        }

    @staticmethod
    def _dump_ip_list(pe, ip_list_rva: List):
        p = 0
        num = 1

        ip_list = []
        while True:
            blob = pe.get_data(ip_list_rva + p, 6)
            p += 6

            (ip1, ip2, ip3, ip4, port) = struct.unpack("<BBBBH", blob)
            # struct stores in big endian
            port = struct.unpack(">H", struct.pack("<H", port))[0]
            if ip1 == 0:
                break

            ip_list.append("%d.%d.%d.%d:%d" % (ip1, ip2, ip3, ip4, port))
            num += 1
        return ip_list

    def handle_error(self, fn, data, msg):
        error_dict = {"file": fn, "hash": self.sha256(data), "status": "fail", "error": msg}
        raise RuntimeError(json.dumps(error_dict, indent=4))

    @staticmethod
    def sha256(data):
        return hashlib.sha256(data).hexdigest()


def status_msg(msg: str, positive=True):
    status = "+" if positive else "-"
    print(f"[{status}] {msg}")


def parse_args() -> Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--files", type=Path, nargs="+", help="List of HZ Rat samples")
    return parser.parse_args()


if __name__ == "__main__":
    results = []
    opts = parse_args()
    for f in opts.files:
        cncs = HZRatExtractor(f).extract_cnc()
        if cncs:
            results.append(cncs)
    pprint(results)
