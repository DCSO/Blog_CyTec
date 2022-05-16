#!/usr/bin/env python3

#
# Author: DCSO CyTec
# https://medium.com/@DCSO_CyTec
#

import json
import base64
import sys

key = b"7dG583EoTWJ"

def rc4crypt(data, key):
    key = bytearray(key)
    data = bytearray(data)

    x = 0
    box = bytearray([i for i in range(256)])
    for i in range(256):
        x = (x + box[i] + key[i % len(key)]) % 256
        box[i], box[x] = box[x], box[i]
    x,y = 0, 0
    for (i,char) in enumerate(data):
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]

        data[i] ^= box[(box[x] + box[y]) % 256]
    return bytes(data)

if len(sys.argv) != 2:
    print("usage: %s <base64 blob>" % sys.argv[0])
    sys.exit(0)

inp = sys.argv[1]
data = base64.b64decode(inp)

j = json.loads(data)

for k in j:
    try:
        j[k] = rc4crypt(base64.b64decode(j[k]),key).decode("ascii")
    except:
        if k == "Los":
            for idx in range(len(j["Los"])):
                j["Los"][idx] = rc4crypt(base64.b64decode(j["Los"][idx]),key).decode("ascii")

print(json.dumps(j,indent=4))
