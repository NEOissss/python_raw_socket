''' Ethernet II header
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | DA | SA | Type | Data | FCS |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	DA      Destination MAC Address (6 bytes)
	SA      Source MAC Address      (6 bytes)
	Type    Protocol Type           (2 bytes)
	Data    Protocol Data           (46 - 1500 bytes)
	FCS     Frame Checksum          (4 bytes)        '''

''' ARP header
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | HRD | PRO |HLN|PLN|  OP | SRC_MAC | SRC_IP| DST_MAC | DST_IP|
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   HRD      Format of hardware address  (2 bytes)
   PRO      Format of protocol address  (2 bytes)
   HLN      Length of hardware address  (1 byte)
   PLN      length of protocol address  (1 byte)
   OP       Operation                   (2 bytes)
   SRC_MAC  Source MAC address          (6 bytes)
   SRC_IP   Source IP address           (4 bytes)
   DST_MAC  Destination MAC address     (6 bytes)
   DST_IP   Destination IP address      (4 bytes)'''

import socket
import struct
import fcntl
import binascii
import commands
from checksum import checksum

DVC = 'enp0s5' # Name of network interface device
IP_PROTO = 0x0800
ARP_PROTO = 0x0806
ARP_OP_REQ = 1 # Request
ARP_OP_REP = 2 # Response

class MyEtherSocket:
    def __init__(self):
        self.src_mac = get_interface_mac(DVC)
        self.dst_mac = get_gateway_mac()

        self.send_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        self.send_sock.bind((DVC,0))

        self.recv_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(IP_PROTO))
        self.recv_sock.setblocking(0)

    def send(self, data):
        packet = MyEtherPacket(self.src_mac, self.dst_mac, IP_PROTO, data)
        output = self.send_sock.send(packet.pack())
        print("Ether: send " + str(output) + " bytes.")

    def recv(self):
        packet = MyEtherPacket()
        while(1):
            data = self.recv_sock.recv(2048)
            packet.unpack(data)
            if packet.dst == self.src_mac:
                return packet.data


class MyEtherPacket:
    def __init__(self, src='', dst='', typ='', data=''):
        self.src = src
        self.dst = dst
        self.type = typ
        self.data = data

    def pack(self):
        frame = struct.pack('!6s6sH', binascii.unhexlify(self.dst), binascii.unhexlify(self.src), self.type) + self.data
        return frame

    def unpack(self, frame):
        [dst, src, self.type] = struct.unpack('!6s6sH', frame[:14])
        self.data = frame[14:]
        self.src = binascii.hexlify(src)
        self.dst = binascii.hexlify(dst)


class MyArpPacket:
    def __init__(self, smac='', sip='', dmac='', dip=''):
        self.hrd = 0x0001 # Only for Ethernet
        self.pro = IP_PROTO
        self.hln = 6
        self.pln = 4
        self.op = ARP_OP_REQ
        self.src_mac = smac
        self.src_ip = sip
        self.dst_mac = dmac
        self.dst_ip = dip

    def pack(self):
        frame = struct.pack('!HHBBH6s4s6s4s',
                            self.hrd, self.pro, self.hln, self.pln, self.op,
                            binascii.unhexlify(self.src_mac),
                            socket.inet_aton(self.src_ip),
                            binascii.unhexlify(self.dst_mac),
                            socket.inet_aton(self.dst_ip))
        return frame

    def unpack(self, frame):
        [self.hrd, self.prp, self.hln, self.pln, self.op,
         src_mac, src_ip, dst_mac, dst_ip] = struct.unpack('!HHBBH6s4s6s4s', frame)

        self.src_mac = binascii.hexlify(src_mac)
        self.src_ip = socket.inet_ntoa(src_ip)
        self.dst_mac = binascii.hexlify(dst_mac)
        self.dst_ip = socket.inet_ntoa(dst_ip)


def get_interface_ip(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', ifname[:15]))[20:24])

def get_interface_mac(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return ''.join(['%02x' % ord(char) for char in info[18:24]])

def get_gateway_ip():
    gw_ip = commands.getoutput('route -n | grep \'UG[ \\t]\' | awk \'{print $2}\'')
    return gw_ip

def get_gateway_mac():
    src_mac = get_interface_mac(DVC)
    src_ip = get_interface_ip(DVC)
    gw_ip = get_gateway_ip()

    send_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    recv_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ARP_PROTO))
    recv_sock.settimeout(5)

    arp_pack = MyArpPacket(src_mac, src_ip, '000000000000', gw_ip)
    eth_pack = MyEtherPacket(src_mac, 'ffffffffffff', ARP_PROTO, arp_pack.pack())

    send_sock.sendto(eth_pack.pack(), (DVC, 0))

    while(1):
        data = recv_sock.recv(2048)
        eth_pack.unpack(data)
        if eth_pack.dst == src_mac:
            arp_pack_rep = MyArpPacket()
            arp_pack_rep.unpack(eth_pack.data[:28])
            if arp_pack_rep.src_ip == arp_pack.dst_ip and arp_pack_rep.dst_ip == arp_pack.src_ip:
                break

    send_sock.close()
    recv_sock.close()
    return arp_pack_rep.src_mac


if __name__ == '__main__':
    sock = MyEtherSocket()
    print(get_gateway_mac())
