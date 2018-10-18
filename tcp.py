''' RFC 793: TCP header
   0                   1                     2                 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                               |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
   |       |           |G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+'''

import socket
import struct
from time import time
from random import randint
from ip import MyIpSocket
from ethr import get_interface_ip, DVC
from checksum import checksum

MSS = 1500
TIME_OUT = 60

CLOSED = 0
ESTABLISHED = 1
CLOSE_WAIT = 2

class MyTcpSocket:
    def __init__(self, host):
        self.src_ip = get_interface_ip(DVC)
        self.src_port = get_open_port()
        self.dst_ip, self.dst_port = socket.getaddrinfo(host, 'http')[0][4]
        print("TCP: " + str((self.src_ip, self.src_port)) + ' to ' + str((self.dst_ip, self.dst_port)))
        self.sock = MyIpSocket(self.src_ip, self.dst_ip)

        # send control
        ''' Advertised window: send_buff
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |       unacked          |       ready to send      |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ '''
        self.seq = 0
        self.cwnd = 1
        self.cwnd_max = 1000

        # recv control
        ''' Congestion window: recv_buff
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                     unacked                       |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ '''
        self.ack = 0
        self.rwnd = 32768
        self.recv_buff = []

        # status
        self.status = CLOSED

    # Three way handshake
    def connect(self):
        send_pack = MyTcpPacket(self.src_ip, self.src_port, self.dst_ip, self.dst_port)
        recv_pack = MyTcpPacket(self.dst_ip, self.dst_port, self.src_ip, self.src_port)
        # 1
        print("TCP: 1st handshake.")
        self.seq = randint(0, 65535)
        send_pack.seqn = self.seq
        send_pack.syn = 1
        self.sock.send(send_pack.pack())
        # 2
        print("TCP: 2nd handshake.")
        while(1):
            try:
                data = self.timeout_recv()
            except TimeoutError:
                # timeout retransmission
                self.sock.send(send_pack.pack())
            else:
                break
        recv_pack.unpack(data)
        # 3
        print("TCP: 3rd handshake.")
        if recv_pack.ackn == self.seq + 1 and recv_pack.syn == 1 and recv_pack.ack == 1 :
            self.seq = recv_pack.ackn
            self.ack = recv_pack.seqn + 1
            self.cwnd_max = recv_pack.window
            send_pack._clear()
            send_pack.seqn = self.seq
            send_pack.ackn = self.ack
            send_pack.ack = 1
            self.sock.send(send_pack.pack())
            print("TCP: connection established!")
            self.status = ESTABLISHED
            return 0
        else:
            print("TCP: connect failed!")
            return -1

    # TCP teardown
    def close(self):
        send_pack = MyTcpPacket(self.src_ip, self.src_port, self.dst_ip, self.dst_port)
        recv_pack = MyTcpPacket(self.dst_ip, self.dst_port, self.src_ip, self.src_port)

        # active teardown
        if self.status == ESTABLISHED:
            print("TCP: active teardown: FIN-WAIT.")
            send_pack.seqn = self.seq
            send_pack.ackn = self.ack
            send_pack.fin = 1
            send_pack.ack = 1
            self.sock.send(send_pack.pack())
            while(1):
                try:
                    data = self.timeout_recv()
                except TimeoutError:
                    # timeout retransmission
                    self.sock.send(send_pack.pack())
                else:
                    break
            recv_pack.unpack(data)
            if recv_pack.ackn == self.seq + 1 and recv_pack.ack == 1 :
                self.seq = recv_pack.ackn
                self.ack = recv_pack.seqn + 1
                # if ack & ack + fin are combined in one segment
                if recv_pack.fin == 1:
                    print("TCP: active teardown: TIME-WAIT.")
                    send_pack._clear()
                    send_pack.seqn = self.seq
                    send_pack.ackn = self.ack
                    send_pack.ack = 1
                    self.sock.send(send_pack.pack())
                    self.status = CLOSED
                    return 0
            while(1):
                try:
                    data = self.timeout_recv()
                except TimeoutError:
                    # timeout retransmission
                    self.sock.send(send_pack.pack())
                else:
                    break
            recv_pack.unpack(data)
            if recv_pack.ackn == self.seq and recv_pack.fin == 1 and recv_pack.ack == 1:
                print("TCP: active teardown: TIME-WAIT.")
                send_pack._clear()
                send_pack.seqn = self.seq
                send_pack.ackn = self.ack
                send_pack.ack = 1
                self.sock.send(send_pack.pack())
                self.status = CLOSED
                return 0

        # passive teardown
        if self.status == CLOSE_WAIT:
            print("TCP: passive teardown: TIME-WAIT")
            send_pack.seqn = self.seq
            send_pack.ackn = self.ack
            send_pack.fin = 1
            send_pack.ack = 1
            self.sock.send(send_pack.pack())

            while(1):
                try:
                    data = self.timeout_recv()
                except TimeoutError:
                    # timeout retransmission
                    self.sock.send(send_pack.pack())
                else:
                    break
            recv_pack.unpack(data)
            if recv_pack.ackn == self.seq + 1 and recv_pack.ack == 1 :
                self.status = CLOSED
                return 0

    # TCP send & resend
    def send(self, data):
        if self.status != ESTABLISHED:
            return -1

        send_pack = MyTcpPacket(self.src_ip, self.src_port, self.dst_ip, self.dst_port)
        recv_pack = MyTcpPacket(self.dst_ip, self.dst_port, self.src_ip, self.src_port)
        send_pack.seqn = self.seq
        send_pack.ackn = self.ack
        send_pack.psh = 1
        send_pack.ack = 1
        self.sock.send(send_pack.pack(data))
        while(1):
            try:
                recv_data = self.timeout_recv()
            except TimeoutError:
                # timeout retransmission
                self.cwnd = 1
                self.sock.send(send_pack.pack())
            else:
                recv_pack.unpack(recv_data)
                if recv_pack.ack == 1 and recv_pack.ackn == self.seq + len(data):
                    self.seq = recv_pack.ackn
                    self.cwnd += 1 * (self.cwnd < self.cwnd_max)
                    break
                else:
                    recv_buff.append(recv_data)

    # TCP recv & advertised wnd
    def recv(self):
        if self.status != ESTABLISHED:
            return -1

        data = ""
        send_pack = MyTcpPacket(self.src_ip, self.src_port, self.dst_ip, self.dst_port)
        recv_pack = MyTcpPacket(self.dst_ip, self.dst_port, self.src_ip, self.src_port)
        send_pack.seqn = self.seq
        send_pack.ackn = self.ack

        while(1):
            try:
                recv_data = self.timeout_recv()
            except TimeoutError:
                send_pack._clear()
                send_pack.ack = 1
                self.sock.send(send_pack.pack())
            else:
                recv_pack.unpack(recv_data)
                # if receive segment with data
                if recv_pack.ack == 1 and recv_pack.data != "":
                    # if in correct order
                    if recv_pack.seqn == self.ack:
                        data += recv_pack.data
                        self.ack += len(recv_pack.data)
                        send_pack.ackn = self.ack
                        send_pack._clear()
                        send_pack.ack = 1
                        self.sock.send(send_pack.pack())
                        # if last segment
                        if recv_pack.fin == 1:
                            #self.status = CLOSE_WAIT
                            break
                    # if duplicate, drop the segment
                    elif recv_pack.seqn < self.ack:
                        continue
                    # not correct order
                    else:
                        send_pack._clear()
                        send_pack.ack = 1
                        self.sock.send(send_pack.pack())
                        self.recv_buff.append(recv_data)
                # read buffer & re-order
                for i in range(len(self.recv_buff)):
                    recv_data = self.recv_buff[i]
                    recv_pack.unpack(recv_data)
                    # if in correct order
                    if recv_pack.seqn == self.ack:
                        data += recv_pack.data
                        self.ack += len(recv_pack.data)
                        send_pack.ackn = self.ack
                        send_pack._clear()
                        send_pack.ack = 1
                        self.sock.send(send_pack.pack())
                        self.recv_buff = self.recv_buff[:i] + self.recv_buff[i+1:]
                        # if last segment
                        if recv_pack.fin == 1:
                            #self.status = CLOSE_WAIT
                            break
                # passive close connection
                if recv_pack.ack == 1 and recv_pack.fin == 1 and recv_pack.ackn == self.seq:
                    print("TCP: passive teardown: FIN-WAIT")
                    self.ack = recv_pack.seqn + 1
                    send_pack.ackn = self.ack
                    send_pack._clear()
                    send_pack.ack = 1
                    self.sock.send(send_pack.pack())
                    self.status = CLOSE_WAIT
                    break
        return data

    def timeout_recv(self):
        recv_pack = MyTcpPacket(self.dst_ip, self.dst_port, self.src_ip, self.src_port)
        start = time()
        while(time() - start < TIME_OUT):
            try:
                data = self.sock.recv()
            except:
                continue
            recv_pack.unpack(data)
            if recv_pack.srcp == self.dst_port and recv_pack.dstp == self.src_port:
                return data
        else:
            print("TCP: send time out!")
            raise TimeoutError


class MyTcpPacket:
    def __init__(self, src='', srcp=0, dst='', dstp=0, data=''):
        self.src = src
        self.srcp = srcp
        self.dst = dst
        self.dstp = dstp
        self.seqn = 0
        self.ackn = 0
        self.offset = 5 # Data offset: 5x4 = 20 bytes
        self.rsrved = 0
        self.urg = 0
        self.ack = 0
        self.psh = 0
        self.rst = 0
        self.syn = 0
        self.fin = 0
        self.window = 32768
        self.chksum = 0
        self.urgp = 0
        self.data = data

    def pack(self, data=''):
        self.data = data
        data_offset = (self.offset << 4) + 0
        flags = self.fin + (self.syn << 1) + (self.rst << 2) + (self.psh << 3) + (self.ack << 4) + (self.urg << 5)
        tcp_header = struct.pack('!HHLLBBHHH',
                                 self.srcp, self.dstp, self.seqn, self.ackn,
                                 data_offset, flags, self.window, self.chksum, self.urgp)
        # Pseudo header for checksum
        pse_header = struct.pack('!4s4sBBH',
                                 socket.inet_aton(self.src), socket.inet_aton(self.dst),
                                 0, socket.IPPROTO_TCP, self.offset * 4 + len(self.data))

        self.chksum = checksum(pse_header + tcp_header + self.data)
        tcp_header = struct.pack("!HHLLBBH", self.srcp, self.dstp, self.seqn, self.ackn, data_offset, flags, self.window)
        # When pack the checksum part, DON'T use network byte order !
        tcp_header += struct.pack('H', self.chksum)
        tcp_header += struct.pack('!H', self.urgp)

        #print "TCP: send header: " + str(['%02X' % ord(c) for c in tcp_header])
        #print "TCP: send header checksum: " + str(hex(self.chksum))
        return tcp_header + self.data

    def unpack(self, data):
        [self.srcp, self.dstp, self.seqn, self.ackn, data_offset, flags, self.window] = struct.unpack('!HHLLBBH', data[0:16])
        # When unpack the checksum part, DON'T use network byte order !
        [self.chksum] = struct.unpack('H', data[16:18])
        [self.urgp] = struct.unpack('!H', data[18:20])

        self.offset = data_offset >> 4
        self.fin = flags & 0x01
        self.syn = flags >> 1 & 0x01
        self.rst = flags >> 2 & 0x01
        self.psh = flags >> 3 & 0x01
        self.ack = flags >> 4 & 0x01
        self.urg = flags >> 5 & 0x01

        self.data = data[self.offset * 4 :]
        pse_header = struct.pack('!4s4sBBH',
                                 socket.inet_aton(self.src), socket.inet_aton(self.dst),
                                 0, socket.IPPROTO_TCP, self.offset * 4 + len(self.data))

        if checksum(pse_header + data) != 0:
            print("TCP: checksum error!")
            self.data = ''

    def _clear(self):
        self.urg = 0
        self.ack = 0
        self.psh = 0
        self.rst = 0
        self.syn = 0
        self.fin = 0
        self.urgp = 0
        self.chksum = 0


class TimeoutError(Exception):
    pass


# Get an available port on local
# Reference from STACKOVERFLOW
def get_open_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("",0))
    port = s.getsockname()[1]
    s.close()
    return port


if __name__ == '__main__':
     s = MyTcpSocket("elsrv2.cs.umass.edu")
     s.connect()
     data = """GET /assignment3.php HTTP/1.1\r\nHost: elsrv2.cs.umass.edu\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:57.0) Gecko/20100101 Firefox/57.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\nCache-Control: max-age=0\r\n\r\n"""
     s.send(data)
     s.recv()
     s.close()
