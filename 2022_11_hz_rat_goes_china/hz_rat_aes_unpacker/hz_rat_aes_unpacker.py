#!/usr/bin/env python3
#
#   Author: DCSO CyTec
#   https://medium.com/@DCSO_CyTec
#
#   Unpack AES 128 bit packed HZ Rat samples
#
#   Example:
#   $ python3 hz_rat_aes_unpacker --files e350dc55f61eda0a7372fb5bbf35fac6d8c928912f3bef75efeaca7c1338093f.exe


import argparse
import re
from argparse import Namespace
from pathlib import Path

from Crypto.Cipher import AES

IDENTIFIER = b"\x0A\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
BLOCK_SIZE = 16


def unpack_and_extract(sample_file: Path):
    status_msg(f"== open file: {sample_file.name} ==")

    sample = bytearray(sample_file.read_bytes())

    if not re.search(IDENTIFIER, sample):
        status_msg(f"No HZ Rat sample", positive=False)
        return

    start_identifier = next(re.finditer(IDENTIFIER, sample))
    status_msg(f"found identifier at position {start_identifier.start()}")

    start_aes_key = start_identifier.start() + len(IDENTIFIER)
    aes_key = sample[start_aes_key:start_aes_key + BLOCK_SIZE]
    status_msg(f"found aes key at position {start_aes_key}")

    start_spacer = start_aes_key + BLOCK_SIZE
    spacer = sample[start_spacer: start_spacer + BLOCK_SIZE]
    if not spacer == b"\x00" * BLOCK_SIZE:
        status_msg(f"No HZ Rat sample", positive=False)
        return

    start_payload = start_spacer + BLOCK_SIZE
    status_msg(f"found payload at position {start_payload}")

    end_payload = find_end_of_payload(sample, start_payload, spacer)

    if end_payload:
        status_msg(f"Payload ends at {end_payload}")
    else:
        status_msg("Couldn't find end of payload", positive=False)
        status_msg(f"No HZ Rat sample", positive=False)
        return

    size_of_payload = end_payload - start_payload
    status_msg(f"size of payload is {size_of_payload}")

    encrypted_payload = sample[start_payload:end_payload]
    decrypted_payload = AES.new(bytes(aes_key), AES.MODE_ECB).decrypt(bytes(encrypted_payload))

    if not decrypted_payload.startswith(b'MZ'):
        status_msg(f"No HZ Rat sample", positive=False)
        return

    extracted_file = Path(".") / f"{sample_file.name}_extracted.bin"
    status_msg(f"extract payload to: {extracted_file}")
    extracted_file.write_bytes(decrypted_payload)


def find_end_of_payload(sample, start_payload, spacer):
    start = start_payload
    last_block = spacer
    for i in range(len(sample)):
        tmp_pos = start + 16 * i
        block = sample[tmp_pos:tmp_pos + 16]
        if block == last_block:
            end_payload = tmp_pos + 16
            return end_payload
    return None


def status_msg(msg: str, positive=True):
    status = "+" if positive else "-"
    print(f"[{status}] {msg}")


def parse_args() -> Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument('--files', type=Path, nargs="+", required=True, help="Packed HZ Rat file")
    return parser.parse_args()


if __name__ == '__main__':
    opts = parse_args()
    for file in opts.files:
        unpack_and_extract(file)
        print()
