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

# Definitions of the protocol messages
MSG_LOGIN = 1
MSG_SELECT_BY_USER = 2
MSG_SELECT_BY_USER_SESSION = 3

class AuditClientHandler(threading.Thread):
	''' This is an active thread that is responsible for serving all
	messages that come in from audit proxy.
	'''

	def __init__(self, serv, params, keyMgr):
		''' Initialize the client handler with the parent server (AuditProxy)
		'''
		threading.Thread.__init__(self)
		self.server = serv
		self.clientList = []
		self.running = True

		# Setup the Python logger
		logFile = 'abls.log'
		logging.basicConfig(filename=logFile,level=logging.DEBUG)

		# Persist the key manager and params
		self.keyMgr = keyMgr
		self.params = params

		# Maintain login state of the user is logged in for this session
		self.loggedIn = False

	def run(self):
		''' The main loop for this client handler thread. Strip out a message,
		parse it according to the protocol, and then invoke the necessary commands.
		'''
		global MSG_LOGIN

		self.shim = DBShim(self.params["AUDIT_USER_DB"], self.keyMgr)
		self.log = DBShim(self.params["LOG_DB"], self.keyMgr)
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

	def login(self, params):
		''' Handle the user login process.
		'''
		# Strip out the username and password
		userNameIndex = params.find(',')
		if (userNameIndex != -1):
			userName = params[0:userNameIndex]
			password = params[userNameIndex + 1:] # format: username,password

			# Fetch the salt from the database (there should only be one user by this name)
			record = self.shim.executeQuery("audit_users", "userName", userName, False)
			if (len(record) == 1):
				salt = record[0]["salt"]
				hashed_password = hashlib.sha512(password + salt).hexdigest()
				if (hashed_password == record[0]["password"]):
					self.loggedIn = True
					return True
				else:
					raise Exception("Invalid password for user: " + userName)
			else:
				raise Exception("Could not find the specified user: " + userName)
		else:
			return False

	def parseMessage(self, message):
		''' Handle the incoming client message by parsing the JSON string and shipping
		it off to the execute method. 
		'''
		print("client message: " + str(message)) # debug

		# Verify that the incoming message conforms to the protocol
		if (len(message) != 2):
			raise Exception("Invalid JSON string retrieved from client.")
		if not (('command' in message) and ('parameters' in message)):
			raise Exception("Invalid JSON string retrieved from client.")

		# Let it rip
		try:
			return self.execute(int(message['command']), message['parameters'])
		except:
			print("Error occured when executing the command")

	def execute(self, command, parameters):
		''' Execute the command (if possible), or throw an exception if it's invalid.
		'''

		# Bring the protocol event IDs into scope
		global MSG_SELECT_BY_USER
		global MSG_SELECT_BY_USER_SESSION

		result = ""

		# Handle the incoming message
		if (command == MSG_SELECT_BY_USER):
			#print("MSG_SELECT_BY_USER")
			#print(parameters[0])
			valueMap = {"userId" : parameters[0]}
			rowMasks = ["userId"]

			try:
				results = self.log.executeMultiQuery("log", valueMap, rowMasks)

				# Format the results to return only the ciphertext
				logList = []
				for i in range(0, len(results)):
					logList.append(results[i][4]) # these are encoded in "hex" - decode with .decode("hex")
				return json.dumps({"result" : True, "message" : json.dumps(logList)})
			except Exception as e:
				print(e)
		elif (command == MSG_SELECT_BY_USER_SESSION):
			#print("MSG_SELECT_BY_USER_SESSION")
			#print(parameters[0])
			valueMap = {"userId" : entry.userId, "sessionId" : entry.sessionId}
			rowMasks = ["userId", "sessionId"]

			try:
				results = self.log.executeMultiQuery("log", valueMap, rowMasks)

				# Format the results to return only the ciphertext
				logList = []
				for i in range(0, len(results)):
					logList.append(results[i][4]) # these are encoded in "hex" - decode with .decode("hex")
				return json.dumps({"result" : True, "message" : json.dumps(logList)})
			except:
				print(e)
		else: 
			raise Exception("Unsupported audit command ID: " + str(command))

		# Default return (if other messages don't work)
		return json.dumps({"result" : False, "message" : "Error parsing message: " + str(command)})

		