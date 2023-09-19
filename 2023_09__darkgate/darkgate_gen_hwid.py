#!/usr/bin/env python3
#
# Author: jaydinbas / dcso.de
#
import hashlib

## FILL THIS IN ###############################################################
computer = b"COMPUTER"
user = b"user"
processor = b"processor info"
product_id = b"xxxxxxxxxxxxxxxxxxxxxxx"
cores = 2

internal_mutex = b"xxxxxx"
###############################################################################

processor += b" @ %d Cores" % cores

print("Using:")
print("  Computer   = %s" % computer.decode("ascii"))
print("  User       = %s" % user.decode("ascii"))
print("  Processor  = %s" % processor.decode("ascii"))
print("  Product ID = %s" % product_id.decode("ascii"))
print("  Int. mutex = %s" % internal_mutex.decode("ascii"))

print("")

def custom_encode(s):
    lookup = b"abcdefKhABCDEFGH"

    out = bytearray()
    for i in range(len(s)):
        upper_nibble = (s[i] & 0xF0) >> 4
        lower_nibble = s[i] & 0x0F

        out.append(lookup[upper_nibble])
        out.append(lookup[lower_nibble])
    return out

def gen_bot_id(computer,user,processor,product_id):
    md5sum = hashlib.md5(product_id+processor+user+computer).digest()
    return custom_encode(md5sum)

def gen_key(bot_id,mutex):
    md5a = hashlib.md5(b"mainhw"+bot_id+mutex).digest()
    return custom_encode(md5a)[:7].lower()


bot_id = gen_bot_id(computer,user,processor,product_id)
print("Bot ID : %s" % bot_id.decode("ascii"))
print("AES key: %s" % gen_key(bot_id,internal_mutex).decode("ascii"))
