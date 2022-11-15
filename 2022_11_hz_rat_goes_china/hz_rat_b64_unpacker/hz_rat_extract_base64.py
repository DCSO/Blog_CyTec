#!/usr/bin/env python3
#
#   Author: DCSO CyTec
#   https://medium.com/@DCSO_CyTec
#
#   Extract ips from HZ Rat samples
#
#   Example:
#   $ python3 hz_rat_b64_unpacker.py --files b4670afde3e88951274780f2128c9584ef80813293ac64c69225fac3926e71ee.exe

import argparse
import base64
from pathlib import Path

import pefile as pefile


def unpack_and_extract(sample_file: Path):
    status_msg(f"== open file: {sample_file.name} ==")

    pe = pefile.PE(sample_file.absolute(), fast_load=True)
    # manually trigger PE resource parsing, skipped due to fast_load=True
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])

    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        status_msg("File has no resources", positive=False)
        return None

    output_file = sample_file.parent / f"{sample_file.name}_extracted.bin"
    if not dump_res_dir(pe, pe.DIRECTORY_ENTRY_RESOURCE, output_file):
        status_msg("No embedded HZ Rat found", positive=False)
        return None

    status_msg(f"Extracted embedded file to {output_file.name}", positive=True)


def dump_res_dir(pe, dir_data, dest_file):
    for entry in dir_data.entries:
        if hasattr(entry, "directory"):
            if dump_res_dir(pe, entry.directory, dest_file):
                return True
        elif hasattr(entry, "data"):
            res_off = entry.data.struct.OffsetToData
            res_size = entry.data.struct.Size

            # print("%08x %d" % (res_off,res_size))
            if res_size < 10:
                continue

            data = pe.get_data(res_off, 10)
            if data.startswith(b"TV"):
                full_data = pe.get_data(res_off, res_size)
                try:
                    plain = base64.b64decode(full_data)
                except:
                    print("Error: Base64 decoding failed")
                    continue

                if not plain.startswith(b'MZ'):
                    continue
                dest_file.write_bytes(plain)
                return True
    return False


def status_msg(msg: str, positive=True):
    status = "+" if positive else "-"
    print(f"[{status}] {msg}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument('--files', type=Path, nargs="+", required=True, help="Packed HZ Rat file")
    return parser.parse_args()


if __name__ == '__main__':
    opts = parse_args()
    for file in opts.files:
        unpack_and_extract(file)
        print()
