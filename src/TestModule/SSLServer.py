import socket
import ssl

# http://bobthegnome.blogspot.com/2007/08/making-ssl-connection-in-python.html
# openssl genrsa 1024 > key
# openssl req -new -x509 -nodes -sha1 -days 365 -key key > cert
# openssl rsa -in key -pubout > key.pub
# openssl req -x509 -nodes -days 7 -newkey rsa:2048 -keyout mycertfile.pem -out mycertfile.pem

from OpenSSL import SSL

context = SSL.Context(SSL.SSLv23_METHOD)
context.use_privatekey_file('../keys/key')
context.use_certificate_file('../keys/cert')

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s = SSL.Connection(context, s)
s.bind(('', 9999))
s.listen(5)

(connection, address) = s.accept()
while True:
    print repr(connection.recv(65535))