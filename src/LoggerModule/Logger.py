'''
File: Logger.py
Author: Christopher A. Wood, caw4567@rit.edu
'''

import sys
import time
import random
import threading
import Queue
import json

# Add in the files from the other modules
sys.path.append("../PolicyEngineModule/")
sys.path.append("../Common")
sys.path.append("../DatabaseModule")
import PolicyManager
import TrafficProxy
import EncryptionModule
import LogEntry
import DBShim

# For hashing log entries
import Keccak 

# For symmetric encryption
from Crypto.Cipher import AES

# For HMAC
import hashlib, hmac

class Logger(threading.Thread):
	''' The logging thread that interacts with other actors to perform perform entry encryption
	'''

	# This can (and should) be changed as needed.
	EPOCH_WINDOW_SIZE = 5

	def __init__(self):
		''' Default constructor.
		'''	
		threading.Thread.__init__(self)
		self.running = False

		# Create the policy actor
		self.manager = PolicyManager.PolicyManager.start()

		# Create the encryption module and Keccak instance
		self.encryptionModule = EncryptionModule.EncryptionModule()
		self.sha3 = Keccak.Keccak()
		
		self.epochKey = {} # key is (user, session)
		self.entityKey = {} # key is (user, session)

		# The initial epoch and entity keys that are used for verification
		self.initialEpochKey = {}
		self.initialEntityKey = {}

		# Create the log queue
		self.queue = Queue.Queue()

	def createSession(self, userId, sessionId):
		''' Initialize the authentication keys that are used when verifying the 
		entries in the log database.
		'''

		# Generate symmetric keys for this session - OLD APPROACH
		#epochKey = hmac.new("\EFx" * 20, str(time.time() * (1000000 * random.random())), hashlib.sha512).hexdigest()
		#entityKey = hmac.new("\EFx" * 20, str(time.time() * (1000000 * random.random())), hashlib.sha512).hexdigest()

		# Generate the epoch and entity keys (both are random 32-bytes strings) - used for verification (integrity) only
		epochKey = Random.new().read(32)
		entityKey = Random.new().read(32)

		# These keys should be encrypted using CPABE for the (verifier role and user role)
		msg = '{"user":' + str(userId) + ',"sessionId":' + str(sessionId) + '"}' 
		policy = self.manager.ask({'command' : 'verifyPolicy', 'payload' : msg})
		encryptedEpochKey = self.encryptionModule.encrypt(epochKey, policy)
		encryptedEntityKey = self.encryptionModule.encrypt(entityKey, policy)

		# Persist the encrypted keys
		# TODO: these were self.logShim
		self.keyShim.replaceInTable("InitialEpochKey", (userId, sessionId, encryptedEpochKey))
		self.keyShim.replaceInTable("InitialEntityKey", (userId, sessionId, encryptedEntityKey))

		# TODO: how to mask the userId and sessionId columns?
		# What key to use to encrypt the user and session IDs?

		#self.logShim.replaceInTable("InitialEpochKey", (userId, sessionId, epochKey))
		#self.logShim.replaceInTable("InitialEntityKey", (userId, sessionId, entityKey))

		self.initialEpochKey[(userId, sessionId)] = epochKey
		self.initialEntityKey[(userId, sessionId)] = entityKey

		# TODO: settle on the relational database schema...

	def getQueue(self):
		''' Fetch this logger's internal queue.
		'''
		return self.queue

	def run(self):
		''' Empty the queue into the log as fast as possible. We are the bottleneck.
		'''
		# Create the log shim.
		self.logShim = DBShim.DBShim("/Users/caw/Projects/SecureLoggingSystem/src/DatabaseModule/log.db")
		self.keyShim = DBShim.DBShim("/Users/caw/Projects/SecureLoggingSystem/src/src/DatabaseModule/key.db")

		self.running = True
		while self.running:
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
		logResults = self.logShim.executeMultiQuery("Log", valueMap)
		epochResults = self.logShim.executeMultiQuery("Epoch", valueMap)

		# Check to see if we are starting a new chain or appending to an existing one.
		if (len(logResults) == 0):
			# Create the initial epoch block
			currKey = self.initialEpochKey[(userId, sessionId)]
			self.epochKey[(userId, sessionId)] = currKey
			#self.logShim.insertIntoTable("EpochKey", (userId, sessionId, currKey))
			self.keyShim.insertIntoTable("EpochKey", (userId, sessionId, currKey))
			lastEpochDigest = hmac.new(currKey, "0", hashlib.sha512).hexdigest()

			# Set the entity key
			self.entityKey[(userId, sessionId)] = self.initialEntityKey[(userId, sessionId)]
			#self.logShim.insertIntoTable("EntityKey", (userId, sessionId, self.entityKey[(userId, sessionId)]))
			self.keyShim.insertIntoTable("EntityKey", (userId, sessionId, self.entityKey[(userId, sessionId)]))

			# Save the epoch digest
			self.logShim.insertIntoTable("Epoch", (userId, sessionId, lastEpochDigest))

			# Create the entry payload
			payload = str(userId) + str(sessionId) + str(0) + str(message) + str(0) # hash of this entry is (user, session, epoch, msg, previous == 0)
		else:
			# Update the epoch/entity key values from the database
			length = len(logResults)
			valueMap = {"userId" : userId, "sessionId" : sessionId}
			#epochKeyResults = self.logShim.executeMultiQuery("EpochKey", valueMap)
			#entityKeyResults = self.logShim.executeMultiQuery("EntityKey", valueMap)
			epochKeyResults = self.keyShim.executeMultiQuery("EpochKey", valueMap)
			entityKeyResults = self.keyShim.executeMultiQuery("EntityKey", valueMap)
			self.epochKey[(userId, sessionId)] = epochKeyResults[len(epochKeyResults) - 1]["key"]
			self.entityKey[(userId, sessionId)] = entityKeyResults[len(entityKeyResults) - 1]["key"]

			# Check to see if we have cycled to a new epoch window
			if (length % self.EPOCH_WINDOW_SIZE) == 0: 
				# Update the epoch key
				currKey = str(self.epochKey[(userId, sessionId)])
				newKey = self.sha3.Keccak((len(bytes(currKey)), currKey.encode("hex")))
				self.epochKey[(userId, sessionId)] = newKey
				#self.logShim.insertIntoTable("EpochKey", (userId, sessionId, newKey))
				self.keyShim.insertIntoTable("EpochKey", (userId, sessionId, newKey))

				# Pull the last epoch block
				length = len(epochResults)
				lastEpoch = epochResults[length - 1]["epochDigest"]

				# Pull the last hash block
				length = len(logResults)
				lastHash = logResults[length - 1]["xhash"]

				# Form the epoch block hash payload
				payload = str(lastEpoch) + str(lastHash)
				digest = hmac.new(newKey, payload, hashlib.sha512).hexdigest()

				# Store the epoch digest...
				self.logShim.insertIntoTable("Epoch", (userId, sessionId, digest))

			# Now, generate the payload for this log entry
			logLength = len(logResults)
			lastHash = logResults[length - 1]["xhash"]
			payload = str(userId) + str(0) + str(logLength) + str(message) + str(lastHash)

		# Finally, query the data to build the final log entry
		valueMap = {"userId" : userId, "sessionId" : sessionId}
		logResults = self.logShim.executeMultiQuery("Log", valueMap)
		epochResults = self.logShim.executeMultiQuery("Epoch", valueMap)

		# Now hash the hash chain entry... But first, build up the data that's needed
		currKey = str(self.epochKey[(userId, sessionId)])
		epochLength = len(epochResults)
		lastEpoch = epochResults[epochLength - 1]["epochDigest"]

		# Here are the elements for the log entry tuple
		xi = self.sha3.Keccak((len(bytes(payload)), payload.encode("hex"))) # not authentication
		yi = hmac.new(currKey, lastEpoch.encode("hex") + xi.encode("hex"), hashlib.sha512).hexdigest()

		# Store the latest entity digest
		currEntityKey = str(self.entityKey[(userId, sessionId)])
		lastEntityDigest = hmac.new(currEntityKey, xi, hashlib.sha512).hexdigest()
		self.logShim.replaceInTable("Entity", (userId, sessionId, lastEntityDigest))
		self.entityKey[(userId, sessionId)] = hmac.new(currEntityKey, "some constant value", hashlib.sha512).hexdigest() # update the keys
		#self.logShim.insertIntoTable("EntityKey", (userId, sessionId, self.entityKey[(userId, sessionId)]))
		self.keyShim.insertIntoTable("EntityKey", (userId, sessionId, self.entityKey[(userId, sessionId)]))

		# Store the elements now
		self.logShim.insertIntoTable("Log", (userId, sessionId, epochLength, str(message), xi, yi))

		# Debug
		print("Inserted the log: " + str((userId, sessionId, epochLength, str(message), xi, yi)))

	def processLogEntry(self, msg):
		''' This method is responsible for processing a single msg retrieved from the traffic proxy.
		'''
		policy = self.manager.ask({'command' : 'policy', 'payload' : msg})
		ciphertext = self.encryptionModule.encrypt(msg, policy)

		# Parse the host application data
		entry = LogEntry.LogEntry(jsonString = msg)

		# See if this is a new session that we need to manage, or if it's part of an existing session
		valueMap = {"userId" : entry.user, "sessionId" : entry.sessionId}
		#results = self.logShim.executeMultiQuery("InitialEpochKey", valueMap)
		results = self.keyShim.executeMultiQuery("InitialEpochKey", valueMap)
		if (len(results) == 0):
			self.createSession(entry.user, entry.sessionId)

		# Now store the event in the log 
		self.addNewEvent(entry.user, entry.sessionId, ciphertext)

	def kill(self):
		''' Terminate this thread.
		'''
		print("Killing the logger thread.")
