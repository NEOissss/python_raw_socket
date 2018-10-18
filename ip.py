''' RFC 791: IP header
   0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+'''

import socket
import struct
from random import randint
from ethr import MyEtherSocket
from checksum import checksum

class MyIpSocket:
    def __init__(self, src, dst):
        self.src = src
        self.dst = dst
        self.sock = MyEtherSocket()
        #print("IP: " + str(self.src) + " to " + str(self.dst))

    def send(self, data):
        packet = MyIpPacket(self.src, self.dst, data)
        self.sock.send(packet.pack())

    def recv(self):
        packet = MyIpPacket()
        while(1):
            data = self.sock.recv()
            packet.unpack(data)
            if packet.proto == socket.IPPROTO_TCP and packet.src == self.dst and packet.dst == self.src:
                return packet.data

class MyIpPacket:
    def __init__(self, src='', dst='', data=''):
        self.ver = 4
        self.ihl = 5 # Internet Header Length
        self.tos = 0 # Type of Service
        self.tl = 0 # total length will be filled by kernel
        self.id = 0
        self.flag = 2 # 2 for DON'T fragment, 1 for MORE fragments, 0 for none of them
        self.offset = 0
        self.ttl = 255
        self.proto = socket.IPPROTO_TCP
        self.chksum = 0 # will be filled by kernel
        self.src = src
        self.dst = dst
        self.data = data

    def pack(self):
        self.tl = self.ihl * 4 + len(self.data)
        self.id = randint(0, 65535)
        ver_ihl = (self.ver << 4) + self.ihl
        flag_offset = (self.flag << 13) + self.offset
        ip_header = struct.pack('!BBHHHBBH4s4s',
                                ver_ihl, self.tos, self.tl, self.id, flag_offset,
                                self.ttl, self.proto, self.chksum,
                                socket.inet_aton(self.src),
                                socket.inet_aton(self.dst))

        self.chksum = checksum(ip_header)
        ip_header = struct.pack('!BBHHHBB', ver_ihl, self.tos, self.tl, self.id, flag_offset, self.ttl, self.proto)
        # When pack the checksum part, DON'T use network byte order !
        ip_header += struct.pack('H', self.chksum)
        ip_header += struct.pack('!4s4s', socket.inet_aton(self.src), socket.inet_aton(self.dst))

        #print "IP: header: " + str(['%02X' % ord(c) for c in ip_header])
        return ip_header + self.data

    def unpack(self, data):
        [ver_ihl, self.tos, self.tl, self.id, flag_offset, self.ttl, self.proto] = struct.unpack('!BBHHHBB', data[0:10])
        # When unpack the checksum part, DON'T use network byte order !
        [self.chksum] = struct.unpack('H', data[10:12])
        [src_ip, dst_ip] = struct.unpack('!4s4s', data[12:20])

        self.ver = (ver_ihl & 0xf0) >> 4
        self.ihl = ver_ihl & 0x0f
        # CAUTION!!!
        self.flag = (flag_offset & 0x6000) >> 13
        self.offset = flag_offset & 0x1fff
        self.src = socket.inet_ntoa(src_ip)
        self.dst = socket.inet_ntoa(dst_ip)
        self.data = data[20 : self.tl]

        # Check the checksum
        ip_header = data[0:20]
        if checksum(ip_header) != 0:
            #raise ChecksumError('IP')
            print("IP: Checksum error!")
            self.data = ''


if __name__ == '__main__':
    p = MyIpPacket("192.188.1.1", "125.2.15.2", "mlgb")
    p.pack()
    print(p.chksum)
