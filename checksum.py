def checksum(data):
    s = 0
    n = len(data) % 2
    for i in range(0, len(data)-n, 2):
        s+= ord(data[i]) + (ord(data[i+1]) << 8)
    if n:
        s+= ord(data[i+2])
    while (s >> 16):
        s = (s & 0xffff) + (s >> 16)
    s = ~s & 0xffff
    return s

if __name__ == '__main__':
    print(hex(checksum('1234567890')))
