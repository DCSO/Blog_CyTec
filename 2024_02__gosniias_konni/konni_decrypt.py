#!/usr/bin/env python3

#
# Author: DCSO (www.dcso.de)
#
# KONNI configuration decryptor
#

import sys
from Cryptodome.Cipher import AES
import hashlib

def is_utf16(s):
    for i in range(1,len(s),2):
        if s[i] != 0:
            return False
    return True

if len(sys.argv) != 3:
    print("usage: %s <service name> <encrypted data file>" % sys.argv[0])
    sys.exit(0)

data = open(sys.argv[2],"rb").read()

initial_counter = data[:16]
data = data[16:]

phrase = sys.argv[1].encode("utf16")[2:] #skip BOM
key = hashlib.sha256(phrase).digest()

cipher = AES.new(key=key,initial_value=initial_counter,mode=AES.MODE_CTR,nonce=b'')
plain = cipher.decrypt(data)

if is_utf16(plain):
    print(plain[::2].decode("ascii"))
else:
    print(plain.decode("ascii"))
