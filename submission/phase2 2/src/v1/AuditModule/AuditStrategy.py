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
import sys
sys.path.append("../DatabaseModule/")
from DBShim import DBShim

class AuditClientHandler(threading.Thread):
	''' This is an active thread that is responsible for serving all
	messages that come in from audit proxy.
	'''

	def __init__(self, serv, keyMgr):
		''' Initialize the client handler with the parent server (AuditProxy)
		'''
		threading.Thread.__init__(self)
		self.server = serv
		self.clientList = []
		self.running = True

		# Setup the Python logger
		logFile = 'abls.log'
		logging.basicConfig(filename=logFile,level=logging.DEBUG)

		# Persist the key manager
		self.keyMgr = keyMgr

		# Maintain login state of the user is logged in for this session
		self.loggedIn = False

	def run(self):
		''' The main loop for this client handler thread. Strip out a message,
		parse it according to the protocol, and then invoke the necessary commands.
		'''
		global MSG_LOGIN

		self.shim = DBShim("/Users/caw/Projects/SecureLoggingSystem/src/DatabaseModule/audit_users.db", self.keyMgr)
		self.log = DBShim("/Users/caw/Projects/SecureLoggingSystem/src/DatabaseModule/log.db", self.keyMgr)
		
		while self.running:
			for client in self.clientList:
				message = client.sock.recv(self.server.BUFFSIZE)
				if message != None and message != "":
					try:
						parsedMsg = json.loads(message)
						if (int(parsedMsg['command']) == MSG_LOGIN):
							if (self.login(parsedMsg['parameters'])):
								client.sock.send('{"result":True,"message":"Login successful."}')
						elif (self.loggedIn == True):
							client.sock.send(self.parseMessage(parsedMsg))
					except Exception as e:
						client.sock.send(str(e))

	