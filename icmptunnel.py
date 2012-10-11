import threading
import socket
import struct
import logging
import select
from Crypto.Cipher import AES
import hashlib

client_socks = {}
server_socks = {}
open_socks = []

MAX_PACKET = 1024
MYMARK = (0x01, 0x01, 0x01, 0xff)
MYKEY = 'my secret key'

SRC_PORT = 1234
SRC_HOST = '127.0.0.1'

DST_PORT = 6666
DST_HOST = '127.0.0.8'


class icmppacket:
    addr = ''
    type = 0
    code = 0
    checksum = 0
    identifier = 0
    sequence = 0
    data = ''

    def decode(self,addr,data):
        if ord(data[0]) != 0:
            raise TypeError

        aesObj = AES.new(hashlib.sha256(MYKEY).digest(), AES.MODE_CBC, '\x00'*16)
        markLen = len(MYMARK)

        # Check MARK
        key_and_data = aesObj.decrypt(data[8:])
        pktKey = tuple(ord(x) for x in key_and_data[:markLen])
        if (pktKey != MYMARK):
            raise TypeError

        # Get Padding size
        padSize = key_and_data[markLen]

        # Real data
        realData = key_and_data[1+markLen+ord(padSize):]

        # Packet data
        self.data = realData
        self.addr = addr[0]
        (self.type, self.code, self.checksum, self.identifier, self.sequence) = struct.unpack('!BBHHH',data[:8])

    def send(self):
        if (self.addr==''):
            return False
        try:
            aesObj = AES.new(hashlib.sha256(MYKEY).digest(), AES.MODE_CBC, '\x00'*16)

            padSize = (1+len(MYMARK) + len(self.data))%16
            if(padSize>0):
                padSize = 16 - padSize

            key_and_data = aesObj.encrypt("".join(chr(x) for x in MYMARK) + chr(padSize) + chr(0)*padSize + self.data)

            packet = struct.pack('!BBHHH%ss' % len(key_and_data),
                self.type,
                self.code,
                0,
                self.identifier,
                self.sequence,
                key_and_data
            )
            packet = struct.pack('!BBHHH%ss' % len(key_and_data),
                self.type,
                self.code,
                self._checksum(packet),
                self.identifier,
                self.sequence,
                key_and_data
            )
            s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
            s.connect((self.addr,0))
            s.send(packet)

        except:
            return False

        return True

    def _checksum(self, packet):
        # http://www.faqs.org/rfcs/rfc1071.html

        if (len(packet)%2):
            packet+=chr(0)

        packet_two_byte_size = len(packet)/2

        packet_two_byte = struct.unpack('!%sH' % packet_two_byte_size, packet)
        checksum = sum(packet_two_byte)

        while (checksum >> 16):
            checksum = (checksum & 0xffff) + (checksum >> 16)

        return ~checksum & 0xffff


def listenicmp():

    s_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
    s.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)

    while 1:
        data, addr = s.recvfrom(65536)
        try:
            newPkt = icmppacket()
            newPkt.decode(addr,data[20:]) #IP header 20 byte

            if (newPkt.identifier > 0) & (newPkt.sequence != 0xffff): # From UDP server to client
                if not (newPkt.sequence in client_socks.keys()):
                    logging.debug("Socket not found")
                    s_udp.connect(("127.0.0.1",newPkt.identifier)) #dest host, dest port
                    open_socks.append(s_udp)
                    client_socks[newPkt.sequence]=s_udp

                client_socks[newPkt.sequence].send(newPkt.data)
            elif (newPkt.sequence != 0xffff): # From client to UDP server
                logging.debug("Server side")
                addr = [key for key,value in server_socks.items() if value == newPkt.sequence][0]
                s_listen.sendto(newPkt.data,addr)
            else:
                print("Icmp packet from %s: %s" % (newPkt.addr,newPkt.data))

        except Exception as e:
            print "error" + str(e)
            continue

def listenudp():

    global s_listen

    s_listen = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s_listen.bind(('',SRC_PORT))

    open_socks.append(s_listen)
    logging.debug("listen sock" + str(s_listen))

    while 1:
        readable, writable, errored = select.select(open_socks,[],[])
        for s in readable:
            data, addr = s.recvfrom(65536)
            if s is s_listen:
                if not addr in server_socks.keys():
                    idSeq =  [val for val in range(1,0xfffe) if val not in server_socks.values()][0]
                    server_socks[addr]=idSeq
                else:
                    idSeq=server_socks[addr]
                try:
                    newPkt = icmppacket()
                    newPkt.addr = DST_HOST #dest host
                    newPkt.type = 0
                    newPkt.code = 0
                    newPkt.identifier = DST_PORT #dest port
                    newPkt.sequence = idSeq
                    newPkt.data = data
                    newPkt.send()
                except:
                    continue
            else:
                idSeq = [key for key,value in client_socks.items() if value == s][0]
                logging.debug("client from " + str(idSeq))

                try:
                    newPkt = icmppacket()
                    newPkt.addr = SRC_HOST #dest host
                    newPkt.type = 0
                    newPkt.code = 0
                    newPkt.identifier = 0 #dest port
                    newPkt.sequence = idSeq
                    newPkt.data = data
                    newPkt.send()
                except:
                    continue

        for s in errored:
            logging.debug("Connection closed"+str(s))
            open_socks.remove(s)

try:
    logging.basicConfig(level=logging.ERROR)
    logging.debug("App started")

    sem1 = threading.Semaphore()
    sem2 = threading.Semaphore(0)
    listen_thread = threading.Thread( target=listenicmp )
    reception_thread = threading.Thread( target=listenudp )
    listen_thread.daemon = True
    listen_thread.start()

    reception_thread.daemon = True
    reception_thread.start()

    logging.debug("Listen thread started")

    while 1:
        data=raw_input('Icmp data:')
        newPkt = icmppacket()
        newPkt.addr = DST_HOST #dest host
        newPkt.type = 0
        newPkt.code = 0
        newPkt.identifier = DST_PORT #dest port
        newPkt.sequence = 0xffff
        newPkt.data = data
        newPkt.send()

except KeyboardInterrupt:
    print "bye bye"