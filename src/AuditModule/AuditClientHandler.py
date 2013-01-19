'''
File: AuditClientHandler.py
Author: Christopher A. Wood, caw4567@rit.edu
'''

import socket
import ssl
import threading
import struct
import string
import Queue
import Logger
import json
import logging
import hashlib
import uuid

# Definitions of the protocol messages
MSG_SELECT_BY_USER = 1
MSG_SELECT_BY_USER_SESSION = 2

class AuditClientHandler(threading.Thread):
	''' This is an active thread that is responsible for serving all
	messages that come in from audit proxy.
	'''

	def __init__(self, serv):
		''' Initialize the client handler with the parent server (AuditProxy)
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

		# Maintain login state of the user is logged in for this session
		self.loggedIn = False

	def run(self):
		''' The main loop for this client handler thread. Strip out a message,
		parse it according to the protocol, and then invoke the necessary commands.
		'''
		while self.running:
			for client in self.clientList:
				message = client.sock.recv(self.server.BUFFSIZE)
				if message != None and message != "":
					if (self.loggedIn == False):
						self.login()
					else:
						self.parseMessage(message)

	def login(self):
		''' Handle the user login process.
		'''
		raise Exception("Not implemented.")
		salt = uuid.uuid4().hex
		hashed_password = hashlib.sha512(password + salt).hexdigest()

	def parseMessage(self, message):
		''' Handle the incoming client message by parsing the JSON string and shipping
		it off to the execute method. 
		'''
		print("client message: " + str(message)) # debug
		parsedMsg = json.loads(jsonString)

		# Verify that the incoming message conforms to the protocol
		if (len(data) != 2):
			raise Exception("Invalid JSON string retrieved from client.")
		if not (('command' in data) and ('parameters' in data)):
			raise Exception("Invalid JSON string retrieved from client.")

		# Let it rip
		try:
			self.execute(int(data['command']), data['parameters'])
		except:
			print("Error occured when executing the command")

	def execute(self, command, parameters):
		''' Execute the command (if possible), or throw an exception if it's invalid.
		'''

		# Bring the protocol event IDs into scope
		global MSG_SELECT_BY_USER
		global MSG_SELECT_BY_USER_SESSION

		# Handle the incoming message
		if (command == MSG_SELECT_BY_USER):
			print("MSG_SELECT_BY_USER")

			# TODO: implement the message logic here

		elif (command == MSG_SELECT_BY_USER_SESSION):
			print("MSG_SELECT_BY_USER_SESSION")

			# TODO: implement the message logic here

		else: 
			raise Exception("Unsupported audit command ID: " + str(command))
		