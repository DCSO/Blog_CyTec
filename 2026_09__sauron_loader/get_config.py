#!/usr/bin/env python3
import argparse
import hashlib
import json
import re
import struct
from pathlib import Path

import pefile
from Crypto.Cipher import Salsa20


SELECTOR = re.compile(
    rb"\xe8\0\0\0\0\x58\x48\x83\xf9\0\x74."
    rb"\x48\x83\xf9\x01\x74.\x48\x8d\x40\x1a\xc3"
    rb"\x48\x8d\x80(?P<offset>.{4})\xc3",
    re.DOTALL,
)


def take_config_blob(pe):
    text = next(s for s in pe.sections if s.Name.startswith(b".text"))
    data = text.get_data()
    match = SELECTOR.search(data)
    if not match:
        raise ValueError("embedded-blob selector not found")
    relative = struct.unpack("<i", match.group("offset"))[0]
    offset = match.start() + 5 + relative
    return data[offset:], text.VirtualAddress + offset


def valid_der(value):
    if len(value) < 2 or value[0] != 0x30:
        return False
    if value[1] < 0x80:
        return value[1] + 2 == len(value)
    count = value[1] & 0x7F
    return 0 < count <= 4 and 2 + count <= len(value) and (
        2 + count + int.from_bytes(value[2 : 2 + count], "big") == len(value)
    )


def parse_layout(plain, dword_count):
    cursor = 5

    def take(size):
        nonlocal cursor
        if cursor + size > len(plain):
            raise ValueError("truncated config")
        value = plain[cursor : cursor + size]
        cursor += size
        return value

    def u32():
        return struct.unpack("<I", take(4))[0]

    def sized():
        return take(u32())

    def wide():
        return sized().decode("utf-16le")

    header = [u32() for _ in range(dword_count)]
    private_key = sized()
    public_key = sized()
    if not valid_der(private_key) or not valid_der(public_key):
        raise ValueError("invalid DER keys")
    group_id, build_id = wide(), wide()
    count = u32()
    if not 1 <= count <= 128:
        raise ValueError("invalid C2 count")
    urls = [wide() for _ in range(count)]
    if not all(url.startswith(("http://", "https://")) for url in urls):
        raise ValueError("invalid C2 URL")
    if any(plain[cursor:]):
        raise ValueError("unparsed config data")

    return header, private_key, public_key, group_id, build_id, urls


def parse_config(plain):
    if len(plain) < 5:
        raise ValueError("truncated config")
    magic = struct.unpack_from("<I", plain)[0]
    flags = plain[4]
    if magic != 0xBAADF00D:
        raise ValueError(f"invalid config magic {magic:#x}")

    matches = []
    for dword_count in range(1, 17):
        try:
            matches.append((dword_count, parse_layout(plain, dword_count)))
        except (ValueError, UnicodeDecodeError, struct.error):
            pass
    if len(matches) != 1:
        raise ValueError(f"expected one config layout, found {len(matches)}")

    dword_count, values = matches[0]
    header, private_key, public_key, group_id, build_id, urls = values
    config = {
        "magic": f"0x{magic:08x}",
        "flags": f"0x{flags:02x}",
        "check_cis": bool(flags & 0x80),
        "check_gov_domain": bool(flags & 0x40),
        "header_dword_count": dword_count,
        #"header_dwords": header,
        "version_words": header[-3:],
        "additional_header_dwords": header[:-3],
        "rsa_private_key_len": len(private_key),
        "rsa_private_key_sha256": hashlib.sha256(private_key).hexdigest(),
        "rsa_public_key_len": len(public_key),
        "rsa_public_key_sha256": hashlib.sha256(public_key).hexdigest(),
        "group_id": group_id,
        "build_id": build_id,
        "c2_urls": urls,
    }
    return config, private_key, public_key


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("dll")
    args = parser.parse_args()
    pe = pefile.PE(args.dll)
    blob, config_rva = take_config_blob(pe)
    key, nonce, size = blob[:16], blob[16:24], struct.unpack_from("<I", blob, 24)[0]
    if 28 + size > len(blob):
        parser.error("encrypted config is truncated")
    plain = Salsa20.new(key=key, nonce=nonce).decrypt(blob[28 : 28 + size])
    config, private_key, public_key = parse_config(plain)

    print(json.dumps(config, indent=2))


if __name__ == "__main__":
    main()
