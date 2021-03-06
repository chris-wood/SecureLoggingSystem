'''
File: Logger.py
Author: Christopher A. Wood, caw4567@rit.edu
'''

import sys
import time
import random
import threading
import traceback
import Queue
import json
import logging # Python logging module
import pickle
from datetime import datetime
import logging

# Add in the files from the other modules
sys.path.append("../PolicyEngineModule/")
sys.path.append("../Common")
sys.path.append("../DatabaseModule")
sys.path.append("../CryptoModule")
from PolicyManager import PolicyManager
import LogProxy
from EncryptionModule import EncryptionModule
import LogEntry
import DBShim

# For hashing log entries
import Keccak 

# For symmetric encryption
from Crypto.Cipher import AES
from Crypto import Random

# For HMAC
import hashlib, hmac

class Logger(threading.Thread):
	''' The logging thread that interacts with other actors to perform perform entry encryption
	'''

	# This can (and should) be changed as needed.
	EPOCH_WINDOW_SIZE = 5

	def __init__(self, params, keyMgr, collector):
		''' Default constructor.
		'''	
		super(Logger, self).__init__()
		self._stop = threading.Event()
		self.params = params

		# Create the policy actor
		self.manager = PolicyManager.start(params, keyMgr)

		# Create the encryption module and Keccak instance
		self.keyMgr = keyMgr
		self.collector = collector
		self.encryptionModule = EncryptionModule(keyMgr)
		self.sha3 = Keccak.Keccak()
		self.aesMode = AES.MODE_CBC

		# The in-memory keys that are maintained (and discarded as needed)
		self.initialEpochKey = {}
		self.initialEntityKey = {}
		self.epochKey = {} # key is (user, session)
		self.entityKey = {} # key is (user, session)
		self.policyKeyMap = {} # key is (user, session, policy)

		# Create the log queue
		self.queue = Queue.Queue()

		# Set up the Python logger
		logFile = 'abls.log'
		logging.basicConfig(filename=logFile,level=logging.DEBUG)

	def createSession(self, userId, sessionId):
		''' Initialize the authentication keys that are used when verifying the 
		entries in the log database.
		'''

		# Generate the epoch and entity keys (both are random 32-bytes strings) - used for verification (integrity) only
		epochKey = Random.new().read(32)
		entityKey = Random.new().read(32)

		# These keys should be encrypted using CPABE for the (verifier role and user role)
		# so they can easily be recovered for verification
		msg = '{"userId":' + str(userId) + ',"sessionId":' + str(sessionId) + ',"payload":' + str(0) + '}' 
		logging.debug("verify msg: " + str(msg))
		policy = self.manager.ask({'command' : 'verifyPolicy', 'payload' : msg})
		encryptedEpochKey = self.encryptionModule.encrypt(epochKey, policy)
		encryptedEntityKey = self.encryptionModule.encrypt(entityKey, policy)

		# Persist the encrypted keys
		self.keyShim.replaceInTable("initialEpochKey", "(userId, sessionId, key, inserted_at)", (userId, sessionId, encryptedEpochKey, datetime.now().ctime()), [True, True, False, False]) 
		self.keyShim.replaceInTable("initialEntityKey", "(userId, sessionId, key, inserted_at)", (userId, sessionId, encryptedEntityKey, datetime.now().ctime()), [True, True, False, False]) 

		logging.debug("adding data to the in-memory dictionaries")
		self.initialEpochKey[(userId, sessionId)] = epochKey
		logging.debug("initial epoch key dict = " + str(self.initialEpochKey))
		self.initialEntityKey[(userId, sessionId)] = entityKey

	def getQueue(self):
		''' Fetch this logger's internal queue.
		'''
		return self.queue

	def endSession(self):
		''' End this session - clear the memory.
		'''
		self.running = False
		self.initialEpochKey = None
		self.initialEntityKey = None
		self.epochKey = None
		self.entityKey = None
		self.policyKeyMap = None

	def run(self):
		''' Empty the queue into the log as fast as possible. We are the bottleneck. >.<
		'''
		# Create the log shim.
		self.logShim = DBShim.DBShim(self.params["LOG_DB"], self.keyMgr)
		self.keyShim = DBShim.DBShim(self.params["KEY_DB"], self.keyMgr)

		while not self.stopped():
			msg = self.queue.get()
			self.processLogEntry(msg)

	def addNewEvent(self, userId, sessionId, message):
		''' Construct a new event to add to the log. It is assumed the epoch key is 
		already initialized before this happens.
		'''
		# Some definitions
		xi = None
		yi = None
		zi = None
		payload = ""
		lastEpochDigest = None

		# Generate the initial log/epoch results
		valueMap = {"userId" : userId, "sessionId" : sessionId}
		logResults = self.logShim.executeMultiQuery("log", valueMap, ["userId", "sessionId"])
		epochResults = self.logShim.executeMultiQuery("epoch", valueMap, ["userId", "sessionId"])

		# Check to see if we are starting a new chain or appending to an existing one.
		if (len(logResults) == 0):
			# Create the initial epoch block
			logging.debug("initial epoch key dict = " + str(self.initialEpochKey))
			currKey = self.initialEpochKey[(userId, sessionId)]
			self.epochKey[(userId, sessionId)] = currKey
			self.keyShim.insertIntoTable("epochKey", "(userId, sessionId, key, inserted_at)", (userId, sessionId, currKey, datetime.now().ctime()), [True, True, False, False])
			logging.debug("****** CURRENT KEY = " + str(currKey))
			lastEpochDigest = hmac.new(currKey, "0", hashlib.sha512).hexdigest()

			# Set the entity key
			self.entityKey[(userId, sessionId)] = self.initialEntityKey[(userId, sessionId)]
			self.keyShim.insertIntoTable("entityKey", "(userId, sessionId, key, inserted_at)", (userId, sessionId, self.entityKey[(userId, sessionId)], datetime.now().ctime()), [True, True, False, False])

			# Save the epoch digest
			self.logShim.insertIntoTable("epoch", "(userId, sessionId, digest, inserted_at)", (userId, sessionId, lastEpochDigest, datetime.now().ctime()), [True, True, False, False])

			# Create the entry payload
			payload = str(userId) + str(sessionId) + str(0) + str(message) + str(0) # hash of this entry is (user, session, epoch, msg, previous == 0)
		else:
			# Update the epoch/entity key values from the database
			length = len(logResults)
			valueMap = {"userId" : userId, "sessionId" : sessionId}
			epochKeyResults = self.keyShim.executeMultiQuery("epochKey", valueMap, ["userId", "sessionId"])
			entityKeyResults = self.keyShim.executeMultiQuery("entityKey", valueMap, ["userId", "sessionId"])
			self.epochKey[(userId, sessionId)] = epochKeyResults[len(epochKeyResults) - 1]["key"]
			self.entityKey[(userId, sessionId)] = entityKeyResults[len(entityKeyResults) - 1]["key"]

			# Check to see if we have cycled to a new epoch window
			if (length % self.EPOCH_WINDOW_SIZE) == 0: 
				# Update the epoch key
				currKey = str(self.epochKey[(userId, sessionId)])
				newKey = self.sha3.Keccak((len(bytes(currKey)), currKey.encode("hex")))
				self.epochKey[(userId, sessionId)] = newKey
				self.keyShim.insertIntoTable("epochKey", "(userId, sessionId, key, inserted_at)", (userId, sessionId, newKey, datetime.now().ctime()), [True, True, False, False])

				# Pull the last epoch block
				length = len(epochResults)
				lastEpoch = epochResults[length - 1]["digest"]

				# Pull the last hash block
				length = len(logResults)
				lastHash = logResults[length - 1]["xhash"]

				# Form the epoch block hash payload
				payload = str(lastEpoch) + str(lastHash)
				digest = hmac.new(newKey, payload, hashlib.sha512).hexdigest()

				# Store the epoch digest...
				self.logShim.insertIntoTable("epoch", "(userId, sessionId, digest, inserted_at)", (userId, sessionId, digest, datetime.now().ctime()), [True, True, False, False])

			# Now, generate the payload for this log entry
			logLength = len(logResults)
			lastHash = logResults[length - 1]["xhash"]
			payload = str(userId) + str(0) + str(logLength) + str(message) + str(lastHash)

		# Finally, query the data to build the final log entry
		valueMap = {"userId" : userId, "sessionId" : sessionId}
		logResults = self.logShim.executeMultiQuery("log", valueMap, ["userId", "sessionId"])
		epochResults = self.logShim.executeMultiQuery("epoch", valueMap, ["userId", "sessionId"])

		# Now hash the hash chain entry... But first, build up the data that's needed
		currKey = str(self.epochKey[(userId, sessionId)])
		epochLength = len(epochResults)
		logging.debug("epoch results = " + str(epochResults))
		lastEpoch = epochResults[epochLength - 1]["digest"]

		# Here are the elements for the log entry tuple
		xi = self.sha3.Keccak((len(bytes(payload)), payload.encode("hex"))) # just a plain old hash
		yi = hmac.new(currKey, lastEpoch.encode("hex") + xi.encode("hex"), hashlib.sha512).hexdigest()

		# Store the latest entity digest
		currEntityKey = str(self.entityKey[(userId, sessionId)])
		lastEntityDigest = hmac.new(currEntityKey, xi, hashlib.sha512).hexdigest()
		self.logShim.replaceInTable("entity", "(userId, sessionId, digest, inserted_at)", (userId, sessionId, lastEntityDigest, datetime.now().ctime()), [True, True, False, False])
		self.entityKey[(userId, sessionId)] = hmac.new(currEntityKey, "some constant value", hashlib.sha512).hexdigest() # update the keys
		self.keyShim.insertIntoTable("entityKey", "(userId, sessionId, key, inserted_at)", (userId, sessionId, self.entityKey[(userId, sessionId)], datetime.now().ctime()), [True, True, False, False])

		# Store the elements now
		self.logShim.insertIntoTable("log", "(userId, sessionId, epochId, message, xhash, yhash, inserted_at)", (userId, sessionId, epochLength, message, xi, yi, datetime.now().ctime()), [True, True, False, False, False, False, False])

		# Debug
		logging.debug("Inserted the log: " + str((userId, sessionId, epochLength, message, xi, yi)))

	def processLogEntry(self, msg):
		''' This method is responsible for processing a single msg retrieved from the log proxy.
		'''
		# Parse the host application data
		entry = LogEntry.LogEntry(jsonString = msg)

		logging.debug("requesting policy")
		policy = self.manager.ask({'command' : 'policy', 'payload' : msg})
		key = None
		iv = None
		logging.debug("Policy for the piece of data: " + str(policy))
		if not ((entry.userId, entry.sessionId, policy) in self.policyKeyMap.keys()):
			iv = Random.new().read(AES.block_size) # we need an IV of 16-bytes, this is also random...
			key = Random.new().read(32)

			# Encrypt the key using the policy and store it in memory and in the database
			encryptedKey = self.encryptionModule.encrypt(key, policy)
			self.policyKeyMap[(entry.userId, entry.sessionId, policy)] = (key, iv)
			self.keyShim.insertIntoTable("policyKey", "(userId, sessionId, policy, key, iv, inserted_at)", (entry.userId, entry.sessionId, policy, encryptedKey, iv, datetime.now().ctime()), [True, True, False, False, False, False])
		else:
			key = self.policyKeyMap[(entry.userId, entry.sessionId, policy)][0]
			iv = self.policyKeyMap[(entry.userId, entry.sessionId, policy)][1]

		# Pad the msg if necessary to make it a multiple of 16
		plaintext = entry.payload
		#print(plaintext)
		if (len(str(plaintext)) % 16 != 0):
			plaintext = plaintext + (' ' * (16 - len(plaintext) % 16))
		ciphertext = AES.new(key, self.aesMode, iv).encrypt(plaintext)
		#print(ciphertext)
		logging.debug("ciphertext = " + str(ciphertext))

		# See if this is a new session that we need to manage, or if it's part of an existing session
		valueMap = {"userId" : entry.userId, "sessionId" : entry.sessionId}
		#results = self.logShim.executeMultiQuery("InitialEpochKey", valueMap)
		try:
			results = self.keyShim.executeMultiQuery("initialEpochKey", valueMap, ["userId", "sessionId"])
		except:
			logging.debug("Error: Unable to update the initialEpochKey table")
			traceback.print_exc(file=sys.stdout)
		if (len(results) == 0):
			self.createSession(int(entry.userId), int(entry.sessionId))

		# Now store the event in the log 
		self.addNewEvent(int(entry.userId), int(entry.sessionId), ciphertext.encode("hex"))

	def stop(self):
		''' Stop this logging thread.
		'''
		self._stop.set()

	def stopped(self):
		''' Check to see if this logging thread was stopped correctly.
		''' 
		return self._stop.isSet()

