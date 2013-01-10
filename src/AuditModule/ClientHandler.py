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
	messages that come in from 
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
				message = client.sock.recv(self.server.BUFFSIZE)
				if message != None and message != "":
					self.handleMessage(message)

	def handleMessage(self, message):
		print("client message: " + str(message))