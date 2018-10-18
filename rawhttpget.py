import os
import sys
from urlparse import urlparse
from tcp import MyTcpSocket

def httpGet(url):
    prs = urlparse(url)
    if prs.path == '':
        path = '/'
    else:
        path = prs.path
    header = 'GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' % (path, prs.hostname)

    sock = MyTcpSocket(prs.hostname)
    sock.connect()
    sock.send(header)
    data = sock.recv()
    data = data[data.find('\r\n\r\n')+4:]
    sock.close()

    if path[-1] == '/':
        fname = 'index.html'
    else:
        fname = path[path.rfind('/')+1:]

    f = open(fname, 'w+')
    f.write(data)
    f.close()

    output = os.system('wget ' + url + ' -O test.html >/dev/null 2>&1')
    output = os.system('diff ' + fname + ' test.html >/dev/null 2>&1')

    if(output==0):
        print("Diff check pass!")
    else:
        print("Diff check failed!")

if __name__ == '__main__':
    argnum = len(sys.argv)
    if argnum == 2:
        url = sys.argv[1]
    else:
        print('Usage: sudo python rawhttpget.py [URL]')
        exit(1)

    httpGet(url)
