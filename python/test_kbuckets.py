#! /usr/bin/env python2.7
# 2.7 or higher needed for bit_length() and other operations

# This is free software, distributed under the terms of
# the GNU General Public License Version 3, or any later version.
# See the COPYING file included in this archive

# jgb@gsyc.es

"""Simple tests for the kbuckets machinery

Tests the kbuckers machinery used in the Python implementation of TeleHash.
In fact it is not intended for serious testing, this is just code I wrote
while implementing kbuckets. It may even not work at all with the current
version of the TeleHash implementation.
"""


import switch
import random
import logging

myEnd = random.getrandbits (160)
print ("My end: %x" % myEnd)

print ("Starts my end with 1?: %s" % switch.testLeftBitEnd (myEnd))

print ("Starts 0 with 1?: %s" % switch.testLeftBitEnd (0))
print ("Starts 1 with 1?: %s" % switch.testLeftBitEnd (1))

for count in range(10):
    end = random.getrandbits (160)
    print "Starts %x with 1?: %s" % (end, switch.testLeftBitEnd (end))
    for prefix in [(1,1), (0,1), (2,2), (3,2), (10,4), (11,4), (12,4), (13,4), (14,4), (15,4)]:
        print ("Starts %x with %s?: %s" % \
                   (end, prefix, switch.testLeftBitsEnd (end, prefix)))

myKBuckets = switch.kBuckets(myEnd)

logging.debug ("Going to store %x" % myEnd)
myKBuckets.storeEnd (myEnd)

#print "%x" % (1 << 159)

#print (1 << 159) & ((1 << 159) + 1)
#print ((1 << 159) & ((1 << 159) + 1)) >> 159
#print (1 << 159) & (1 << 158)

for num in range(100):
    end = random.getrandbits (160)
    logging.debug ("Going to store %x" % end)
    myKBuckets.storeEnd (end)

print ("Ends closest to %x" % end)
closest = myKBuckets.getClosestEnds (end, 5)
for element in closest:
    print ("  %x" % element)
