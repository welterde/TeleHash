#! /usr/bin/env python2.7
# 2.7 or higher needed for bit_length() and other operations

# This is free software, distributed under the terms of
# the GNU General Public License Version 3, or any later version.
# See the COPYING file included in this archive

# jgb@gsyc.es

"""Some tests to understand how to calculate xor distances for TeleHash Ends.

Tests are naive, and probably irrelevant. They are just the code I wrote to
understand how xor distance works in Python
"""

import hashlib

someIPPs = ["85.48.154.240:40476",
            "85.48.154.240:41542",
            "107.20.214.94:52394",
            "50.18.184.21:43435",
            "107.20.214.94:35888",
            ]

def getEnd (ip,port):
    return hashlib.sha1(ip + ":" + str(port)).hexdigest()

def getIPP (string):
    return string.split(':')

someEnds = [getEnd(*(getIPP(string))) for string in someIPPs]

def hex_to_int (hex_string):
    num = 0
    for c in hex_string:
        num *= 16
        if "0" <= c <= "9":
            num += ord(c) - ord("0")
        elif "a" <= c <= "f":
            num += ord(c) - ord("a") + 10
        else:
            raise ValueError(c)
    return num

someEndsAsInt = [hex_to_int(end) for end in someEnds]

someEndsAsInt2 = [int(end,16) for end in someEnds]

someEndsAsInt3 = [long(end,16) for end in someEnds]

someEndsBackAsHex = [hex(end) for end in someEndsAsInt]

someEndsBackAsHex2 = ["%x" % end for end in someEndsAsInt]

someEndsBackAsInt = [long(end,16) for end in someEndsBackAsHex]

def hexToLong (hex):
    """Convert an hex string into a long int"""

    return long (hex, 16)

def longToHex (long):
    """Convert a long int into an hex string"""

    return "%x" % long

someEndsXOR = [longToHex(hexToLong (end) ^ hexToLong(someEnds[0])) for end in someEnds]

someBuckets = [hexToLong(end).bit_length()-1 for end in someEndsXOR]

def xorDistance (a, b):
    # Distance calculation taken from 
    # http://stackoverflow.com/questions/2255177/finding-the-exponent-of-n-2x-using-bitwise-operations-logarithm-in-base-2-of
    # Should be checked!
    a = hex_to_int (a)
    b = hex_to_int (b)
    xor = a ^ b
    dist = int(round(math.log(xor, 2), 0)) # 2**101 generates 100.999999999
    return dist

print "SomeIPPs: " + str(someIPPs)
print
print "SomeEnds: " + str(someEnds)
print
print "SomeEnds as int: " + str(someEndsAsInt)
print
print "SomeEnds as int (converted with int()): " + str(someEndsAsInt2)
print
print "SomeEnds as int (converted with long()): " + str(someEndsAsInt3)
print
print "SomeEnds back as hex (with hex()): " + str(someEndsBackAsHex)
print
print "SomeEnds back as hex (with '%x'): " + str(someEndsBackAsHex2)
print
print "SomeEnds back as int: " + str(someEndsBackAsInt)
print
print "someEndsXOR: " + str(someEndsXOR)
print
print "someBuckets: " + str(someBuckets)
