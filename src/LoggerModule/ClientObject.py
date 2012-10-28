'''
File: ClientObject.py
Author: Christopher A. Wood, caw4567@rit.edu
'''

import socket
import threading
import struct
import string

class ClientObject(object):
	'''
	Simple wrapper for the socket and address information of a client.
	This is just a glorified struct...
	'''
	def __init__(self, clientInfo):
		'''
		Initialize the fields.
		'''
		self.sock = clientInfo[0]
		self.address = clientInfo[1]

	def update(self, message):
		'''
		Exposed method that can be used to send data back to the client, if needed.
		'''
		self.sock.send(message.encode())