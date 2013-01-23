import socket, ssl, pprint

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# require a certificate from the server
ssl_sock = ssl.wrap_socket(s,
                keyfile="../keys/key",
                certfile="../keys/cert",
                ca_certs="../keys/cert",
                cert_reqs=ssl.CERT_REQUIRED)

ssl_sock.connect(("localhost", 9998))

print repr(ssl_sock.getpeername())
print ssl_sock.cipher()
print pprint.pformat(ssl_sock.getpeercert())

ssl_sock.write("testing")
ssl_sock.write("testing")
ssl_sock.write("testing")
ssl_sock.write("testing")
ssl_sock.write("testing")
ssl_sock.write("testing")
ssl_sock.write("after")
ssl_sock.write("after")
ssl_sock.write("after")
ssl_sock.write("after")
ssl_sock.write("after")
#print data

#ssl_sock.close()