import sys
import struct
import binascii
from Cryptodome.PublicKey import ECC
from Cryptodome.Protocol.DH import key_agreement, import_x25519_public_key
from Cryptodome.Cipher import AES
from hashlib import sha512

CHUNK_SIZE = 1048576

def kdf(x):
    #print("Shared secret: %s" % binascii.hexlify(x))
    return sha512(x).digest()

# This is the ECC key set by the attackers
ecc = ECC.import_key(open("ecc_key.bin","rb").read())

data = open("TitanHide.log.safepay","rb").read()
metadata = data[-80:]

(file_size,ecc_pub_used,ecc_file,enc_lvl,is_chacha) = struct.unpack_from("<Q32s32sBB",metadata)

print("Total size: %d" % file_size)
print("Enc Level : %d" % (enc_lvl))
print("Is ChaCha : %d" % (is_chacha))

# Assert the ECC key used matches the one we patched in
assert ecc.public_key().export_key(format='raw') == ecc_pub_used

# The file's ECC public key
ecc_pub = import_x25519_public_key(ecc_file)

# Derive key material
file_key = key_agreement(static_priv=ecc,static_pub=ecc_pub,kdf=kdf)

if not is_chacha:
    cipher = AES.new(key=file_key[:32],iv=file_key[32:48],mode=AES.MODE_CBC)
else:
    sys.exit(0)

count = 0
p = 0
while True:
    if (count + 1) % enc_lvl != 0:
        chunk = data[p:(p+CHUNK_SIZE)]
        plain = cipher.decrypt(chunk)
        print("Decrypted chunk")

        p += CHUNK_SIZE
        if p > file_size:
            break
        count += 1
    else:
        count = 0
        off = (11-enc_lvl) * CHUNK_SIZE
        p += off
        if p > file_size:
            break
