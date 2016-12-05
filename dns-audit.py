#!/usr/bin/env python

import dns.resolver
import os
import sys
import time
import array
import socket
import struct
import select
from _thread import get_ident


ICMP_ECHOREPLY = 0  # Echo reply (per RFC792)
ICMP_ECHO = 8  # Echo request (per RFC792)
ICMP_ECHO_IPV6 = 128  # Echo request (per RFC4443)
ICMP_ECHO_IPV6_REPLY = 129  # Echo request (per RFC4443)
ICMP_MAX_RECV = 2048  # Max size of incoming buffer

MAX_SLEEP = 1000

if sys.platform == "win32":
    # On Windows, the best timer is time.clock()
    default_timer = time.clock
else:
    # On most other platforms the best timer is time.time()
    default_timer = time.time


def get_parser():
    """Get parser object for script xy.py."""
    from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
    parser = ArgumentParser(description=__doc__,
                            formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument("-f", "--file",
                        dest="filename",
                        type=lambda x: is_valid_file(parser, x),
                        help="write report to FILE",
                        metavar="FILE")
    parser.add_argument("-n",
                        dest="n",
                        default=10,
                        type=int,
                        help="how many lines get printed")
    parser.add_argument("-q", "--quiet",
                        action="store_false",
                        dest="verbose",
                        default=True,
                        help="don't print status messages to stdout")
    return parser


def main():
    file = open(os.path.normpath("C:/Users/mzarglis/Desktop/python/ehealth.txt"))
    for line in file:
        line = line.strip()
        ip = line.strip('\n')
        req = formatn(ip)
        query(req,ip)
    return None


# Format Query for Reverse Lookup
def formatn(ip):
    req = '.'.join(reversed(ip.split("."))) + ".in-addr.arpa"
    return req


# Query Dns Server
def query(request,ip):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['10.105.105.100']

    try:
        answers = resolver.query(request, "PTR")
        if len(answers) > 0:
            # print("Resolving  " + request)
            with open(os.path.normpath("C:/Users/mzarglis/Desktop/python/results.txt"), 'a') as file:
                file.write(ip + "\n")
                r = ping.single_ping(ip,ip,2000,1,32)
                if r[0] is None:
                    file.write("Host Unreachable" + '\n')
                else:
                    file.write('Host responded to ICMP in ' + str(round(r[0],2)) + " ms" + '\n')
            for rdata in answers:
                with open(os.path.normpath("C:/Users/mzarglis/Desktop/python/results.txt"), 'a') as file:
                    file.write(str(rdata) + '\n')
            # print(rdata)
            with open(os.path.normpath("C:/Users/mzarglis/Desktop/python/results.txt"), 'a') as file:
                file.write('\n')

    except Exception as e:
        s = repr(e)
        with open(os.path.normpath("C:/Users/mzarglis/Desktop/python/results.txt"), 'a') as file:
            file.write("No PTR record for " + ip + "\n")
            r = single_ping(ip, ip, 2000, 1, 32)
            if r[0] is None:
                file.write("Host Unreachable" + '\n' + '\n')
            else:
                file.write('Host responded to ICMP in ' + str(round(r[0], 2)) + " ms" + '\n' + '\n')


def single_ping(destIP, hostname, timeout, mySeqNumber, numDataBytes,
                myStats=None, quiet=False, ipv6=False, verbose=True):
    """
    Returns either the delay (in ms) or None on timeout.
    """
    delay = None

    if ipv6:
        try:  # One could use UDP here, but it's obscure
            mySocket = socket.socket(socket.AF_INET6, socket.SOCK_RAW,
                                     socket.getprotobyname("ipv6-icmp"))
            mySocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        except OSError as e:
            if verbose:
                print("failed. (socket error: '%s')" % str(e))
                print('Note that python-ping uses RAW sockets'
                      'and requiers root rights.')
            raise  # raise the original error
    else:

        try:  # One could use UDP here, but it's obscure
            mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                     socket.getprotobyname("icmp"))
            mySocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        except OSError as e:
            if verbose:
                print("failed. (socket error: '%s')" % str(e))
                print('Note that python-ping uses RAW sockets'
                      'and requires root rights.')
            raise  # raise the original error

    my_ID = (os.getpid() ^ get_ident()) & 0xFFFF

    sentTime = _send(mySocket, destIP, my_ID, mySeqNumber, numDataBytes, ipv6)
    if sentTime is None:
        mySocket.close()
        return delay

    if myStats is not None:
        myStats.pktsSent += 1

    recvTime, dataSize, iphSrcIP, icmpSeqNumber, iphTTL \
        = _receive(mySocket, my_ID, timeout, ipv6)

    mySocket.close()

    if recvTime:
        delay = (recvTime-sentTime)*1000
        if not quiet:
            if ipv6:
                host_addr = hostname
            else:
                try:
                    host_addr = socket.inet_ntop(socket.AF_INET, struct.pack(
                        "!I", iphSrcIP))
                except AttributeError:
                    # Python on windows dosn't have inet_ntop.
                    host_addr = hostname

            if verbose:
                print("%d bytes from %s: icmp_seq=%d ttl=%d time=%.2f ms" % (
                      dataSize, host_addr, icmpSeqNumber, iphTTL, delay)
                      )

        if myStats is not None:
            myStats.pktsRcvd += 1
            myStats.totTime += delay
            if myStats.minTime > delay:
                myStats.minTime = delay
            if myStats.maxTime < delay:
                myStats.maxTime = delay
    else:
        delay = None
        if not quiet:
            print("Request timed out.")

    return delay, (recvTime, dataSize, iphSrcIP, icmpSeqNumber, iphTTL)


def _send(mySocket, destIP, myID, mySeqNumber, numDataBytes, ipv6=False):
    """
    Send one ping to the given >destIP<.
    """
    # destIP  =  socket.gethostbyname(destIP)

    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    # (numDataBytes - 8) - Remove header size from packet size
    myChecksum = 0

    # Make a dummy heder with a 0 checksum.
    if ipv6:
        header = struct.pack(
            "!BbHHh", ICMP_ECHO_IPV6, 0, myChecksum, myID, mySeqNumber
        )
    else:
        header = struct.pack(
            "!BBHHH", ICMP_ECHO, 0, myChecksum, myID, mySeqNumber
        )

    padBytes = []
    startVal = 0x42
    # 'cose of the string/byte changes in python 2/3 we have
    # to build the data differnely for different version
    # or it will make packets with unexpected size.
    if sys.version[:1] == '2':
        _bytes = struct.calcsize("d")
        data = ((numDataBytes - 8) - _bytes) * "Q"
        data = struct.pack("d", default_timer()) + data
    else:
        for i in range(startVal, startVal + (numDataBytes - 8)):
            padBytes += [(i & 0xff)]  # Keep chars in the 0-255 range
        # data = bytes(padBytes)
        data = bytearray(padBytes)

    # Calculate the checksum on the data and the dummy header.
    myChecksum = _checksum(header + data)  # Checksum is in network order

    # Now that we have the right checksum, we put that in. It's just easier
    # to make up a new header than to stuff it into the dummy.
    if ipv6:
        header = struct.pack(
            "!BbHHh", ICMP_ECHO_IPV6, 0, myChecksum, myID, mySeqNumber
        )
    else:
        header = struct.pack(
            "!BBHHH", ICMP_ECHO, 0, myChecksum, myID, mySeqNumber
        )

    packet = header + data

    sendTime = default_timer()

    try:
        mySocket.sendto(packet, (destIP, 1))  # Port number is irrelevant
    except OSError as e:
        print("General failure (%s)" % str(e))
        return
    except socket.error as e:
        print("General failure (%s)" % str(e))
        return

    return sendTime


def _receive(mySocket, myID, timeout, ipv6=False):
    """
    Receive the ping from the socket. Timeout = in ms
    """
    timeLeft = timeout/1000

    while True:  # Loop while waiting for packet or timeout
        startedSelect = default_timer()
        whatReady = select.select([mySocket], [], [], timeLeft)
        howLongInSelect = (default_timer() - startedSelect)
        if whatReady[0] == []:  # Timeout
            return None, 0, 0, 0, 0

        timeReceived = default_timer()

        recPacket, addr = mySocket.recvfrom(ICMP_MAX_RECV)

        ipHeader = recPacket[:20]

        iphVersion, iphTypeOfSvc, iphLength, iphID, iphFlags, iphTTL, \
            iphProtocol, iphChecksum, iphSrcIP, iphDestIP = struct.unpack(
                "!BBHHHBBHII", ipHeader)

        if ipv6:
            icmpHeader = recPacket[0:8]
        else:
            icmpHeader = recPacket[20:28]

        icmpType, icmpCode, icmpChecksum, icmpPacketID, icmpSeqNumber \
            = struct.unpack("!BBHHH", icmpHeader)

        # Match only the packets we care about
        if (icmpType != 8) and (icmpPacketID == myID):
            dataSize = len(recPacket) - 28
            return timeReceived, (dataSize + 8), iphSrcIP, icmpSeqNumber, \
                iphTTL

        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            return None, 0, 0, 0, 0


def _checksum(source_string):
    """
    A port of the functionality of in_cksum() from ping.c
    Ideally this would act on the string as a series of 16-bit ints (host
    packed), but this works.
    Network data is big-endian, hosts are typically little-endian
    """
    if (len(source_string) % 2):
        source_string += "\x00"
    converted = array.array("H", source_string)
    if sys.byteorder == "big":
        converted.bytewap()
    val = sum(converted)

    val &= 0xffffffff  # Truncate val to 32 bits (a variance from ping.c, which
    # uses signed ints, but overflow is unlikely in ping)

    val = (val >> 16) + (val & 0xffff)  # Add high 16 bits to low 16 bits
    val += (val >> 16)  # Add carry from above (if any)
    answer = ~val & 0xffff  # Invert and truncate to 16 bits
    answer = socket.htons(answer)

    return answer

if __name__ == "__main__":
    args = get_parser().parse_args()
