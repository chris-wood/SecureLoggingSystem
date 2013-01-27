'''
File: AuditClientObject.py
Author: Christopher A. Wood, caw4567@rit.edu
'''

import socket
import threading
import struct
import string

class AuditClientObject(object):
	''' Simple wrapper for the socket and address information of a client.
	This is just a glorified struct...
	'''
	def __init__(self, socket, addr, connstream):
		''' Initialize the fields.
		'''
		self.sock = socket
		self.address = addr
		self.connstream = connstream

	def update(self, message):
		''' Exposed method that can be used to send data back to the client, if needed.
		'''
		self.sock.send(message.encode())