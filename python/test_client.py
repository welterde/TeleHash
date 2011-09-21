#! /usr/bin/env python

# This is free software, distributed under the terms of
# the GNU General Public License Version 3, or any later version.
# See the COPYING file included in this archive

# jgb@gsyc.es

"""Simple client to get seed from TeleHash main seed switch.

Just connects to a seed (telehash.org) and prints the received telex.
Uses twisted.
"""

try:
    from twisted.internet.protocol import DatagramProtocol
    from twisted.internet import reactor
except ImportError, e:
    raise RuntimeError("You need to install twisted")

from json import dumps as encode_json, loads as decode_json

import socket

# We define some constants
MAX_TELEX_BYTESIZE = 1400

SEEDS = [
    (socket.gethostbyname('telehash.org'), 42424)
    ]

TELEX_GET_SEEDS = encode_json({'+end': '3b6a6...'})

class Print(DatagramProtocol):

    def datagramReceived(self, data, (host, port)):
        print "Received from %s:%d:" % (host, port)
        telexContent = decode_json(data)
        print telexContent
        (host,port_str) = telexContent['_to'].split(':')
        port = int(port)
        print host,port
        if (host,port) not in SEEDS:
            SEEDS.append ((host,port))
        print 'SEEDS:'
        print SEEDS
        self.transport.write(TELEX_GET_SEEDS, SEEDS[-1])

reactor.listenUDP(9999, Print()).write(TELEX_GET_SEEDS, SEEDS[0])
reactor.run()
