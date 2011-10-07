#! /usr/bin/env python2.7
# 2.7 or higher needed for bit_length() and other operations

# This is free software, distributed under the terms of
# the GNU General Public License Version 3, or any later version.
# See the COPYING file included in this archive

# jgb@gsyc.es

"""Naive TeleHash implementation

It works only in part. Documentation is still completely missing.
Using this is completely up to you.

Most of the output of the program comes to a file "switch.log",
which includes traces for the main data structures and telexes
sent/received.
"""

# Use logging and configure it to the more verbose level
import logging
logging.basicConfig(filename='switch.log',
                    filemode='w',
                    level=logging.DEBUG,
                    format='%(levelname)s(%(asctime)s): %(message)s',
                    )

try:
    from twisted.internet.protocol import DatagramProtocol
    from twisted.internet import reactor
    from twisted.internet import task
except ImportError, e:
    raise RuntimeError("You need to install twisted")

from json import dumps as encode_json, loads as decode_json

import socket
import hashlib
import math
import random
import time
import bisect
import operator

# We define some constants
MAX_TELEX_BYTESIZE = 1400

#SEEDS = []
SEEDS = [
    (socket.gethostbyname('telehash.org'), 42424)
    ]

NULL_IPP = ("0.0.0.0", "0")

# All known switches, keyed by "IP:Port"
knownSwitches = {}

# Conversion functions

def hexToLong (hex):
    """Convert an hex string into a long int"""

    return long (hex, 16)

def longToHex (long):
    """Convert a long int into an hex string"""

    return "%x" % long

def IPPToString (ipp):
    """Convert (IP, port) to string ip:port."""

    (ip, port) = ipp
    return ip + ":" + str(port)

def StringToIPP (string):
    """Convert "ip:port" to an IPP (ip, port)"""

    (ip, port) = string.split(':')
    port = int(port)
    return (ip, port)

def IPPToStringEnd (ipp):
    """Convert IP, port to End (hash), as hex string"""

    (ip, port) = ipp
    return hashlib.sha1(ip + ":" + str(port)).hexdigest()

def IPPToLongEnd (ipp):
    """Convert IP, port to End (hash), as long int"""

    (ip, port) = ipp
    return hexToLong (hashlib.sha1(ip + ":" + str(port)).hexdigest())

def bitLenght (long):
    """Returns (bit length - 1) of long

    This means that long >= 2^bitLenght and long < 2^(bitLength+1).
    If long == 0, -1 is returned
    If long == 11111111...11111 (160 ones, in binary), 159 is returned
    """

    return long.bit_length() - 1

def bitLenghtHex (hex):
    """Returns (bit length - 1) of hex (considered as string)

    Same considerations than bitLength
    """

    return hexToLong(hex).bit_length() - 1

def bitLengthXOR (a, b):
    """Returns (bit length - 1) of the XOR of two longs"""

    xor = a ^ b
    return bitLenght (xor)

def bitLengthXORHex (a, b):
    """Returns (bit length - 1) of the XOR of two hex strings"""

    xor = hexToLong(a) ^ hexToLong(b)
    return bitLenght (xor)

def testLeftBitEnd (end):
    """True if leftmost (most significant) bit from end is 1, False otherwise

    end is a 160-bits integer"""

    if end & (1 << 159):
        return True
    else:
        return False

def testLeftBitsEnd (end, prefix):
    """True if leftmost (most significant) bits from end are prefix, False otherwise

    end: a 160-bits integer
    prefix: (prefixNumber, length) pair to be tested as prefix"""

    (prefixNumber, length) = prefix
    # Build a mask with 1 in the bits to compare
    mask = 1
    for count in range(length-1):
        mask <<= 1
        mask += 1
    mask <<= (160 - length)
    # Move prefix to the left, so that it can be truly compared as a prefix
    prefixNumber <<= (160 - length)
    return (end & mask) == prefixNumber


class Telex:
    """Telex object, for parsing and analyzing a telex"""
    
    def __init__(self, data):
        """Initialize telex by JSON-decoding parameter.
        
        Doesn't handle TypeError, which will be raised if decoding fails
        """

        # Telex as dictionary, obtained from parsing JSON
        self.content = decode_json(data)
        # Telex as parsed object, with all information in it properly organized
        # Keys in the dictionary are elements names ('to', 'br', etc.)
        # For each element, a dictionary is maintained:
        #  'content': content of the element, as parsed from JSON
        #  'kind': kind of element: 'Command', 'Header', 'Signal'
        #  'value': value of the element, as an object adequate for it
        #               E.g. (host, port) for 'to' 
        self.parsed = {}

    def str(self):
        return str(self.content)

    def str_parsed(self):
        return str(self.parsed)

    def parse(self):
        # Identify and classify all fields
        for field in self.content:
            if field[:1] == '.':
                kind = 'Command'
            elif field[:1] == '_':
                kind = 'Header'
            elif field[:1] == '+':
                kind = 'Signal'
            else:
                kind = 'Other'
            self.parsed[field] = {'kind': kind} 

        # Now, parse particularities of some fields
        for field in self.content:
            if field == '_to':
                # Convert IP:Port strings to IPP
                self.parsed[field]['value'] = StringToIPP(self.content[field])
            elif field == '_ring':
                # Content is an integer to construct the line id
                self.parsed[field]['value'] = int(self.content[field])
            elif field == '_line':
                # Content is an integer
                self.parsed[field]['value'] = int(self.content[field])
            elif field == '.see':
                # Convert IP:Port strings to IPP
                self.parsed[field]['value'] = []
                for addr in self.content[field]:
                    self.parsed[field]['value'].append(StringToIPP (addr))
            elif field == '+pop':
                # Content should be "proto:address", such as "th:IPP"
                (proto, addr) = self.content[field].split(':',1)
                if proto == 'th':
                    ipp = StringToIPP(addr)
                self.parsed[field]['value'] = (proto, ipp)
            elif field == '+end':
                # Content should be an end (hash of an IPP), as a string
                # Convert it to integer
                self.parsed[field]['value'] = hexToLong(self.content[field])

    def has_field (self, field):
        """Check wether the telex has given field"""
        return self.content.has_key(field)

    def get_to (self):
        return self.parsed['_to']['value']

    def get_ring (self):
        return self.parsed['_ring']['value']

    def get_line (self):
        return self.parsed['_line']['value']

    def get_see (self):
        return self.parsed['.see']['value']

    def get_pop (self):
        return self.parsed['+pop']['value']

    def get_end (self):
        return self.parsed['+end']['value']


class kBuckets(object):
    """Data structure managing the routing table (k-buckets)"""
        
    def __init__(self, myEnd):

        self.myEnd = myEnd
        # Branches is a dictionary with an entry per branch in the binary tree.
        # Each branch corresponds in fact to all Ends starting with its binary prefix
        # Each branch in the binary tree corresponds to one or more k-buckets
        # We start with two branches, with prefixes 0 and 1.
        # When one of them is full, and it is in the close part of the
        # network (that is, myEnd starts by that prefix), it gets split.
        # And so on.
        # In addition to the prefix, we store also the number of meaningful bits
        # For example, (0,1) means: prefix is 0, prefix is 1 bit long
        # For each branch, two ordered lists are maintained:
        #  . ready: those ends ready to communicate (open line with them)
        #  . spare: those ends not currently ready to communicate
        #     (they could be being probed, or not)
        self.branches = {(0,1): self.emptyBranch(), 
                         (1,1): self.emptyBranch()}

        # kBuckets are a list of elements. Each element in the list is a reference
        # to the branch holding Ends for that bucket. We start with all elements
        # being 0 (only one branch). When the bucket is complete and split,
        # some Buckets will become 0 and other(s) will become 1 (according to
        # Kademlia k-buckets rules).
        if testLeftBitEnd(self.myEnd):
            # Further ends start with 0, closer ends start with 1 
            self.kBuckets = [(1, 1) for i in range (160)]
            self.kBuckets[159] = (0, 1)
        else:
            # Further ends start with 1, closer ends start with 0
            self.kBuckets = [(0, 1) for i in range (160)]
            self.kBuckets[159] = (1, 1)

    def emptyBranch (self):
        return ({'ready': [], 'spare': []})

    def getOtherKind (self, kind):
        """Get the other kind for lists in branches"""
        
        if kind == 'ready':
            return('spare')
        else:
            return('ready')

    def printBranches (self):
        """Print branches contents"""

        logging.debug("Showing content of branches{}")
        for branch in self.branches.keys():
            for kind in self.branches[branch].keys():
                logging.debug("  Branch (%s): (%x, %d)" % \
                                  (kind, branch[0], branch[1])) 
                for end in self.branches[branch][kind]:
                    logging.debug("    %x" % end)

    def splitBranch (self, branch):
        """Split a branch into its two subbranches.

        For example, split branch 001 in 0010 0011,
        moving ends to new branches according to their prefix,
        and finally deleting the branch being split
        """

        (prefix, length) = branch
        # Prepare new prefixes
        length += 1
        zeroPrefix = prefix << 1
        onePrefix = (prefix << 1) + 1
        zeroBranch = (zeroPrefix, length)
        oneBranch = (onePrefix, length)
        # Now, new branches
        self.branches[zeroBranch] = self.emptyBranch()
        self.branches[oneBranch] = self.emptyBranch()
        #logging.debug ("zeroBranch: %s, oneBranch: %s" % (zeroBranch, oneBranch))
        # Fill the new branches with ends from the old one, and delete it
        for kind in self.branches[branch].keys():
            for anEnd in self.branches[branch][kind]:
                if testLeftBitsEnd(anEnd, zeroBranch):
                    # This end starts by zeroPrefix
                    self.branches[zeroBranch][kind].append(anEnd)
                else:
                    # This end starts by onePrefix
                    self.branches[oneBranch][kind].append(anEnd)
        del self.branches[branch]
        # Update kBuckets with new branches
        if testLeftBitsEnd(self.myEnd, zeroBranch):
            # Further ends start with onePrefix, closer ends start by zeroPrefix
            self.kBuckets[160-length] = oneBranch
            for bucket in range(160-length):
                self.kBuckets[bucket] = zeroBranch
        else:
            # Further ends start with zeroPrefix, closer ends start by onePrefix
            self.kBuckets[160-length] = zeroBranch
            for bucket in range(160-length):
                self.kBuckets[bucket] = oneBranch

    def getBranch (self, end):
        """Get the key in branches corresponding to the bucket corresponding to end"""

        bucket = bitLengthXOR(end, self.myEnd)
        if bucket == -1:
            # This is only if end is myEnd, should not happen...
            bucket = 0
        return (self.kBuckets[bucket])

    def storeEnd (self, end, kind):
        """Store an End in the routing table, if it is not already present

        Manages k-Buckets and bit tree as needed, splitting, if needed, a full
        bucket to make some room.
        kind is important: space can only be full in the 'ready' list
        If the End is already stored, does nothing at all.

        Returns True if the end was stored, False if not (it was already present,
        or there was no room for it in the corresponding bucket)"""

        branch = self.getBranch(end)
        otherKind = self.getOtherKind (kind)
        if end in self.branches[branch][kind]:
            # End already stored
            stored = False
        else:
            # Not already stored
            if (kind == 'spare') or (len (self.branches[branch][kind]) < 20):
                # There is still some room, or this is the spare list:
                #  store in the branch
                logging.debug('Storing in branch %s (%s) the end %x' % \
                                  (str(branch), kind, end))
                self.branches[branch][kind].append (end)
                stored = True
            elif testLeftBitsEnd(self.myEnd, branch):
                # This branch includes myEnd, and is full, so we split it
                # First of all, we need to calculate new branch prefixes
                # For that, we append 0 and 1, to the right, to the previous branch
                logging.debug('Need to split branch %s for end %x' % (str(branch), end))
                self.splitBranch (branch)
                # Store the new end (recurively call myself)
                stored = self.storeEnd (end, kind)
            else:
                # Branch is full, but it is in the furthest end, 
                # so we just store it in the spare list
                logging.debug ("Branch %s is full, storing %x in spare list" % (str(branch), end))
                self.branches[branch]['spare'].append (end)
                stored = True
        if end in self.branches[branch][otherKind]:
            # End is of the wrong kind, remove it from there anyway
            self.branches[branch][otherKind].remove(end)
            logging.debug ("KBuckets: %x removed from branch %s (%s)" % \
                               (end, self.branches[branch], otherKind))
        if stored:
            # End was stored, log new status of data structures
            self.printBranches()
            logging.debug ("KBuckets: %s" % self.kBuckets)
        return stored

    def getClosestEnds (self, end, howMany=5):
        """Returns the howMany Ends closer to end (XOR distance)

        For now, algorithm is simple: get closest ends from the same bucket
        (closest ends should be in the same bucket). If there are not enough
        ends in the bucket, just add myEnd, and return a shorter list.

        Only serve ends in the 'ready' lists.

        To be more strict when there aren't enough buckets, we should be 
        considering all those buckets with prfix length longer than the one
        with end, since all of them are candidates to have closest ends (not
        as close than those in the same bucket, however). This is granted by
        an interesting proprierty of the binary tree: closest ends are always
        in the same subtree; and by an interesting propriety of how kBuckets
        is constructed: only split to longer prefixes, only one for a given
        prefix length, except for thew two deeper buckets at any moment.
        """

        branch = self.getBranch(end)
        distances = [(other, end ^ other) \
                         for other in self.branches[branch]['ready'] \
                         if other != end]
        sortedDistances = sorted(distances, key=operator.itemgetter(1))
        logging.debug ("sortedDistances to end %x (branch %s)" % (end, branch))
        for element in sortedDistances:
            logging.debug ("  %x, %d" % element)
        closest = [element[0] for element in sortedDistances[:howMany]]
        if len(closest) < howMany:
            # FIXME: Not enough ends, other buckets should be checked
            # For now, just add myEnd
            closest.append(self.myEnd)
        return closest

class TeleHashSwitch(DatagramProtocol):

    def __init__(self):

        # My addressed (IPP and its hash)
        self.myIPP = None
        # My end, as an integer
        self.myEnd = None

        # Number of received datagrams
        self.recvDatagramsNo = 0

        # When I last tried my IPP
        self.lastTriedMyIPP = 0

        # When lines were last scanned
        self.lastScanLines = 0

        # When to show some stats
        self.lastStats = 0

        # Switches for which I have inteterest in communcation
        # (and keeping a line)
        # Dictionary keyed by IPP. Each entry contains a dictionary with fields:
        #  . state: 'line' Line State, _line received, established line
        #           'ringing' Ringing State, _ring received, but not established line yet
        #           'opening' Opening State, no _ring or _line received yet
        #  . end: End id for this IPP
        #  . myRing: ring number I used to establish the line
        #  . partnerRing: ring number the other party proposed
        #  . line: line number (for convenience)
        #  . lineOpen: when I moved to Ringing State, as returned by time.time()
        #  . br: bytes received in valid telexes from IPP
        #  . bs: bytes sent in telexes to IPP
        #  . tr: valid telexes received from IPP
        #  . ts: telexes sent to IPP
        #  . lastSent: when I last sent a telex to IPP as returned by time.time()
        #  . lastSeen: when I last saw a telex from IPP, as returned by time.time()
        #  All times can be initialized to 0, which is a "void" value
        self.lines = {}

        # Mapping from ends to IPPs
        # Maybe this could be stored in kBuckets, but for now, let's keep it separate
        self.endIPPs = {}

        # KBucketsData will be created when I know myEnd
        self.kBucketsData = None

    def showLines(self):
        """Print the content of lines"""

        for ipp in self.lines.keys():
            logging.info(' Lines [%s]:' % IPPToString(ipp))
            logging.info('  state: %s' % self.lines[ipp]['state'])
            logging.info('  end: %s' % longToHex(self.lines[ipp]['end']))
            logging.info('  line: %d, myRing: %d, partnerRing: %d' %
                         (self.lines[ipp]['line'],
                          self.lines[ipp]['myRing'],
                          self.lines[ipp]['partnerRing']))
            logging.info('  br: %d, bs: %d, tr: %d, ts: %d' % 
                         (self.lines[ipp]['br'], self.lines[ipp]['bs'],
                          self.lines[ipp]['tr'], self.lines[ipp]['ts']))
            logging.info('  lastSent: %s' %
                         time.ctime(self.lines[ipp]['lastSent']))
            logging.info('  lineOpen: %s' % 
                         time.ctime(self.lines[ipp]['lineOpen']))
            logging.info('  lastSeen: %s' %
                         time.ctime(self.lines[ipp]['lastSeen']))

    # Telexes buffered to send (usually as a result of sending a message, or doing
    #   some housekeeping). They are still not send waiting for (maybe) new fields
    # Dictionary, keyed by destination IPP (only one telex per destination).
    # The value for each key is a telex as Python dictionary
    toSend = {}

    def startProtocol(self):
        """Will be called when a transport is connected to this Twisted protocol

        Prepare everything before the switch actually runs, and start the game.
        """

        now = time.time()
        self.lastScanLines = now
        self.lastStats = now
        # Fake the time when I tried my IPP, so I try it asap
        self.lastTriedMyIPP = now - 5
        # Set up the pendingIssues function to be called every second
        periodic = task.LoopingCall(self.pendingIssues)
        periodic.start(1.0) # call every second

    def pendingIssues(self):
        """Run pending periodic or scheduled tasks (run every period)"""

        now = time.time()
        logging.debug("Period expired")
        if not self.myIPP:
            # I still don't know my IPP
            if now > self.lastTriedMyIPP + 5:
                # Dial seeds to learn my IPP (every 5 periods)
                self.lastTriedMyIPP = now
                self.dialList(SEEDS, hexToLong('3b6a6'))
        # Scan lines to send I'm Alive telexes
        if now > self.lastScanLines + 3:
            logging.debug("5 periods passed, scanning lines")
            self.lastScanLines = now
            self.ImAlive(now)
        self.sendToSend ()
        # Show some stats
        if now > self.lastStats + 10:
            self.lastStats = now
            logging.info("Lines now:")
            self.showLines()
            self.kBucketsData.printBranches()

    def dialList (self, toIPPs, end):
        """Dial an end at a list of IPPs"""

        logging.info("Going to dial end at %s: %x." % (str(toIPPs), end))
        for ipp in toIPPs:
            self.addToSend (ipp, {'+end': longToHex(end)})

    def ImAlive (self, now):
        """Send I'm Alive messages if period without outgoing activity expired"""

        logging.info("Going to check I'm Alives to send")
        for ipp in self.lines.keys():
            if self.lines[ipp]['lastSent'] + 10 < now:
                self.addToSend (ipp, {'+end': longToHex(self.myEnd)})

    def toOpeningState (self, ipp):
        """First notice of an IPP, either before sending or after receiving.

        Move it to Opening State: update lines to include a new entry for it,
        and store some initial values. Update endIPPs too.
        """

        myRing = random.randint(1, 32768)
        self.lines[ipp] = {'state': 'opening',
                           'end': IPPToLongEnd(ipp),
                           'myRing': myRing,
                           'partnerRing': 0,
                           'line': 0,
                           'lineOpen': 0,
                           'br': 0,
                           'bs': 0,
                           'tr': 0,
                           'ts': 0,
                           'lastSeen': 0,
                           'lastSent': 0,
                           }
        self.endIPPs[IPPToLongEnd(ipp)] = ipp
        logging.info("New line with %s: %s" % \
                         (IPPToString(ipp), str (self.lines[ipp])))

    def toRingingState (self, ipp, telex):
        """Move from Opening State to Ringing State"""

        partnerRing = telex.get_ring()
        self.lines[ipp]['partnerRing'] = partnerRing
        self.lines[ipp]['line'] = partnerRing * \
            self.lines[ipp]['myRing']
        self.lines[ipp]['state'] = 'ringing'    
        logging.info("In Ringing State (%s): %s" % \
                         (IPPToString(ipp), str(self.lines[ipp])))

    def toLineState (self, ipp, telex):
        """Move from Opening or Ringing State to Line State"""
        
        line = telex.get_line()
        self.lines[ipp]['line'] = line
        if self.lines[ipp]['partnerRing'] == 0:
            self.lines[ipp]['partnerRing'] = line / self.lines[ipp]['myRing']
        self.lines[ipp]['state'] = 'line'
        self.lines[ipp]['lineOpen'] = time.time()
        logging.info("In Line State (%s): %s" % \
                         (IPPToString(ipp), str(self.lines[ipp])))

    def updateKBuckets (self, ipps):
        """Update kBuckets with a list of ipps.

        Usually the list of ipps was received in a .see command.
        """

        for ipp in ipps:
            end = IPPToLongEnd (ipp)
            if self.kBucketsData.storeEnd(end, 'ready'):
                # End was stored. Therefore, it is new, and we want to use
                # it in the future in the routing table.
                # Ping an end, via my seed, so that it can answer back
                #  (this is just to let it open its NAT for me, when answering
                #  to the pop with a direct UDP datagram)
                # FIXME: in fact this could be done with other switches.
                self.addToSend (SEEDS[0], {'+end': longToHex(end),
                                           '+pop': 'th:' + IPPToString(self.myIPP)
                                           })
                # Now, dial myEnd
                logging.debug("Dialing %s for myEnd (%x)" % (str(ipp), self.myEnd))
                self.addToSend(ipp, {'+end': longToHex(self.myEnd)})


    def addToSend (self, to, content=None):
        """Add field with content to telex to be sent to "to"
            
        Creates a new entry in toSend, if needed, and populates it with
        content (dictionary with fields and respective content).
        If content is None, just prepares a new "template" telex if
        no telex was being prepared for this destination."""

        # We need a new template telex for this destination
        needTemplate = False

        if to not in self.lines.keys():
            # New switch, include it in lines
            self.toOpeningState (to)
        if to in self.toSend.keys():
            # We have previous fields for this destination,
            # check if there are repeated fields for it (if we have content to send).
            if content != None:
                for field in content.keys():
                    if field in self.toSend[to].keys():
                        # Found one repeated field, so send the previous telex and reset
                        self.send (to)
                        needTemplate = True
                        break
        else:
            # This is a new destination for this round, new template telex needed
            needTemplate = True
        if needTemplate:
            # Build a "template" telex, with common fields
            self.toSend[to] = {'_to': IPPToString(to)}
            self.toSend[to]['_br'] = self.lines[to]['br']
            if self.lines[to]['line'] != 0:
                self.toSend[to]['_line'] = self.lines[to]['line']
            else:
                self.toSend[to]['_ring'] = self.lines[to]['myRing']
        if content != None:                    
            # There is some extra content to fill in
            for field in content.keys():
                self.toSend[to][field] = content[field]
        logging.debug("Telex to send %s: %s." % (str(to), str(self.toSend[to])))
        #logging.debug("Telexes ready to send now %s." % (str(self.toSend)))

    def sendToSend (self):
        """Send all pending datagrams"""
            
        for to in self.toSend.keys():
            self.send (to)
        self.toSend = {}

    def send(self, to):
        """Send the telex in toSend for the specified destination.

        to: IPP of the destination switch
        The telex will be stored as a dictionary in self.toSend[to]
        """

        telexJSON = encode_json(self.toSend[to], separators=(',',':'))
        logging.info("Sending telex to %s: %s." % (IPPToString(to), telexJSON))
        try:
            self.transport.write(telexJSON, to)
            self.lines[to]['bs'] += len(telexJSON)
            self.lines[to]['ts'] += 1
            self.lines[to]['lastSent'] = time.time()
        except socket.error, (value, message):
            logging.info("Error sending telex: [Errno %d] %s", value, message)

    def datagramReceived(self, data, (host, port)):
        """An UDP datagram was received by the switch. Act accordingly"""

        try:
            recvTelex = Telex(data)
            fromIPP = (host, port)
        except TypeError:
            logging.error("Malformed telex from %s:%d: %s." % \
                              (host, port, data))
            return
        self.recvDatagramsNo = self.recvDatagramsNo + 1
        self.toSend = {}
        logging.info("Received from %s:%d: %s." % (host, port, data))
        #logging.debug("Telex as dictionary: %s." % recvTelex.str())
        recvTelex.parse()
        #logging.debug( "Telex parsed: %s." % recvTelex.str_parsed())
        if fromIPP not in self.lines.keys():
            # First direct UDP datagram from this IPP: it is already traversing my NAT.
            # So now it opened its NAT (if any) for me with this telex
            # and I already opened mine for it (this datagram came in)
            # So, I have direct, duplex UDP communication
            # Create an new entry in lines for it, entering Opening State
            self.toOpeningState(fromIPP)
        if not self.myIPP:
            # I still don't know my IPP, check "to" to know it
            self.myIPP = recvTelex.get_to()
            self.myEnd = IPPToLongEnd (self.myIPP)
            logging.info("Learned my IPP and End: %s: %x." % \
                              (IPPToString(self.myIPP), self.myEnd))
            # Initialize the data structure maitaining k-Buckets
            self.kBucketsData = kBuckets(self.myEnd)
            self.endIPPs[self.myEnd] = self.myIPP
            # Now, dial myEnd and tap to it (just in case)
            logging.debug("Dialing myEnd (%x), and tapping" % self.myEnd)
            self.addToSend (SEEDS[0], {'+end': longToHex(self.myEnd),
                                       '.tap': [{'is': {'+end': longToHex(self.myEnd)},
                                                 'has': ['+pop']}]
                                       })

        if self.lines[fromIPP]['state'] == 'opening':
            # Cannot accept telexes, but can check if they have _ring and
            # move to Ringing State, or _line and move to Line State
            if recvTelex.has_field('_ring'):
                self.toRingingState (fromIPP, recvTelex)
            elif recvTelex.has_field('_line') and \
                    (recvTelex.get_line() % self.lines[fromIPP]['myRing'] == 0):
                self.toLineState (fromIPP, recvTelex)
            else:
                # No _ring, no correct line, so ignore it
                logging.error("Bad telex (no _ring or valid _line) from %s: %s" % \
                                  (IPPToString (fromIPP), recvTelex))
                return
        if self.lines[fromIPP]['state'] == 'ringing':
            if recvTelex.has_field('_line') and \
                    (recvTelex.get_line() == self.lines[fromIPP]['line']):
                self.toLineState (fromIPP, recvTelex)
            elif (not recvTelex.has_field('_ring')) or \
                    (recvTelex.get_ring() != self.lines[fromIPP]['partnerRing']):
                # No correct _ring, so ignore it
                logging.error("Bad telex (no valid _ring) from %s: %s" % \
                                  (IPPToString (fromIPP), recvTelex))
                return
        if self.lines[fromIPP]['state'] == 'line':
            if (not recvTelex.has_field('_line')) or \
                    (recvTelex.get_line() != self.lines[fromIPP]['line']):
                # No correct _line, so ignore it
                logging.error("Bad telex (no valid _line) from %s: %s" % \
                                  (IPPToString (fromIPP), recvTelex))
                return
        # If we reached this point, telex is valid, update entry in lines
        self.lines[fromIPP]['br'] += len(data)
        self.lines[fromIPP]['tr'] += 1
        self.lines[fromIPP]['lastSeen'] = time.time()

        # Now process commands
        if recvTelex.has_field('.see'):
            # Received an array of IPPs that are of interest to me.
            # Include corresponding Ends in kBuckets 
            logging.debug("See received: %s" % str(recvTelex.get_see()))
            self.updateKBuckets(recvTelex.get_see())

        # Now process signals that require some action
        if recvTelex.has_field('+end'):
            # +end received, respond with a .see of closer switches
            #  (or myself if I'm the closest), and ping via others
            end = recvTelex.get_end()
            logging.debug("+end received: %x" % end)
            self.kBucketsData.storeEnd(end, 'ready')
            closestEnds = self.kBucketsData.getClosestEnds(end, 4)
            closestIPPs = []
            for closestEnd in closestEnds:
                try:
                    closestIPPs.append(self.endIPPs[closestEnd])
                except KeyError:
                    logging.error('End %x not in endIPPs dictionary' % closestEnd)
            self.addToSend (fromIPP, {'.see': closestIPPs})
            # Ping the end, via my seed, so that it can answer back
            #  (this is just to let it open its NAT for me, when answering
            #  to the pop with a direct UDP datagram)
            # FIXME: in fact this could be done with other switches instead of seed.
            # FIXME: and probably this should be done periodically.
            self.addToSend (SEEDS[0], {'+end': longToHex(end),
                                       '+pop': 'th:' + IPPToString(self.myIPP)
                                       })

        if recvTelex.has_field('+pop'):
            logging.debug("+pop received: %s" % str(recvTelex.get_pop()))
            # Answer back a hello message, just in case my NAT needs to be opened
            (proto, popIPP) = recvTelex.get_pop()
            self.addToSend (popIPP)

        self.sendToSend ()

if __name__ == "__main__":
    myTeleHashSwitch = TeleHashSwitch()
    reactor.listenUDP(port=0, protocol=myTeleHashSwitch, maxPacketSize=1400)
    reactor.run()
