import pefile
import struct
from Cryptodome.Cipher import ChaCha20
from hashlib import sha512
import mmh3
import argparse
import binascii
from pathlib import Path


# pre-generated ECC key:
ecc_priv = binascii.unhexlify("e751fa701757d0232ffb94b5813589d1ae541e8b71d5b9f6f0185c0fb6cb213f")
ecc_pub  = binascii.unhexlify("562962943d156cc277a044f5e86cf43d393ef47931bcacd5281d832db8db1843")

def main(opts):
    PE_FILE = pefile.PE(opts.binary)

    for section in PE_FILE.sections:
        raw_data = section.get_data()

        murmurhash = int.from_bytes(raw_data[:4], "little")
        data_len = int.from_bytes(raw_data[4:8], "little")

        data = raw_data[8:data_len+8]
        new_key = sha512(opts.key.encode()).digest()[:56]
        cipher_obj = ChaCha20.new(key=new_key[:32], nonce=new_key[32:])
        plaintext = cipher_obj.decrypt(data)

        if mmh3.hash(plaintext, seed= 0xffffffff, signed=False) != murmurhash:
            continue

        print("Found config")

        new_plaintext = ecc_pub + plaintext[32:]
        new_hash = mmh3.hash(new_plaintext,seed=0xFFFFFFFF,signed=False)

        # rebuild section blob
        enc_section = ChaCha20.new(key=new_key[:32],nonce=new_key[32:]).encrypt(new_plaintext)
        new_config = struct.pack("<II",new_hash,data_len) + enc_section

        # rebuild executable
        off = section.PointerToRawData
        print("Offset: %08x" % off)
        binary = bytearray(open(opts.binary,"rb").read())
        for i in range(len(new_config)):
            binary[off+i] = new_config[i]

        open("locker.dll","wb").write(binary)
        print("[+] Wrote 'locker.dll'")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument('-b', '--binary', type=Path, help="Path to SafePay binary", required=True)
    parser.add_argument('-k', '--key', type=str, help="the PASS key for the SafePay", required=True)
    return  parser.parse_args()

if __name__ == "__main__":
    opts = parse_args()
    main(opts)
