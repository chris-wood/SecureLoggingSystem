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
from Logger import Logger

# The Python logging module
import logging

class ClientHandler(threading.Thread):
	''' This is an active thread that is responsible for serving all
	messages that come in from the keylogger. It simply strips
	them out of the socket and forwards them along to the logger
	actor via a message dictionary.
	'''

	def __init__(self, serv, params, keyMgr, collector):
		''' Initialize the client handler with the parent server (LogProxy)
		'''
		threading.Thread.__init__(self)
		self.server = serv
		self.clientList = []
		self.running = True
		self.params = params
		self.collector = collector

		# Set up the Python logger
		logFile = 'abls.log'
		logging.basicConfig(filename=logFile,level=logging.DEBUG)

		# Set the properties for this session (forward along the key manager)
		self.logger = Logger(self.params, keyMgr, collector)
		self.queue = self.logger.getQueue()
		self.logger.start()

	def run(self):
		''' The main loop for this cliet handler thread. Simply strip messages
		out of the socket and send them to the logger for processing.
		'''
		while self.running:
			for client in self.clientList:
				try:
					message = client.sock.recv(self.server.BUFFSIZE)
					#message = client.connstream.read() # this was for SSL-wrapped information
					if message != None and message != "":
						self.handleMessage(message)
					else:
						self.running = False
				except:
					self.running = False

		logging.debug("Terminating the client handler")
		self.logger.endSession()
		self.logger.stop()

	def handleMessage(self, message):
		''' Handle a client message.
		'''
		logging.debug("client message: " + str(message))
		self.queue.put(message)
