'''
File: VerifyCrawler.py
Author: Christopher A. Wood, caw4567@rit.edu
'''

import socket
import time
import threading
import struct
import string
import Logger
import DBShim
import Logger

import Keccak # The SHA-3 candidate, of course

# For HMAC
import hashlib, hmac

class VerifyCrawler(threading.Thread):
	'''
	This is an active thread that is responsible for serving all
	messages that come in from the keylogger. It simply strips
	them out of the socket and forwards them along to the logger
	actor via a message dictionary.
	'''

	def __init__(self, server):
		''' Constructor that stores the log server information.
		'''
		threading.Thread.__init__(self)
		self.server = server
		self.running = True

		# Generate the used entry bucket
		self.usedBin = {}
		self.MAX_TRIES = 10 # This can (and should) be configured by expermientation.

	def run(self):
		''' The main thread loop for this verifier.
		'''
		# Create the shim
		self.shim = DBShim.DBShim(self.server)

		# Run the crawler loop indefinitely...
		while self.running:
			(userId, sessionId) = self.selectRow()

			# Query the keys from the database
			valueMap = {"userId" : userId, "sessionId" : sessionId}
			epochKey = self.shim.executeMultiQuery("InitialEpochKey", valueMap)
			key1 = epochKey[0]["key"]
			entityKey = self.shim.executeMultiQuery("InitialEntityKey", valueMap)
			key2 = entityKey[0]["key"]

			# Query the last digest from the database
			entityDigest = self.shim.executeMultiQuery("Entity", valueMap)
			digest = entityDigest[len(entityDigest) - 1]["digest"]			

			# Query for the log now.
			logResult = self.shim.executeMultiQuery("Log", valueMap)
			log = {}
			log[(userId, sessionId)] = []
			for i in range(0, len(logResult)):
				log[(userId, sessionId)].append([userId, sessionId, logResult[i]["epochId"], logResult[i]["message"], logResult[i]["xhash"], logResult[i]["yhash"]])

			# Verify.
			self.strongestVerify(userId, sessionId, log, str(key1), str(key2), digest, Logger.Logger.EPOCH_WINDOW_SIZE)
			time.sleep(5)

	def selectRow(self):
		''' Select a row from the database to perform a strong verification on
		'''
		userId = sessionId = 0
		
		foundNewRow = False
		tries = 0
		while not foundNewRow:
			result = self.shim.randomQuery("Log")
			userId = result[0]["userId"]
			sessionId = result[0]["sessionId"]
			if not ((userId, sessionId) in self.usedBin):
				self.usedBin[(userId, sessionId)] = 0
				foundNewRow = True

			# Upgrade all the instances for 
			for key in self.usedBin.keys():
				self.usedBin[key] = self.usedBin[key] + 1

			# See if we ran past the try cap
			tries = tries + 1
			if (tries >= self.MAX_TRIES):
				tk1, tk2, maxNum = 0, 0, 0
				for (k1, k2) in self.usedBin.keys():
					if (self.usedBin[(k1, k2)] > maxNum):
						maxNum = self.usedBin[(k1, k2)]
						tk1 = k1
						tk2 = k2

				del self.usedBin[(tk1, tk2)]
				userId = tk1
				sessionId = tk2
				foundNewRow = True # we're going to retry a previous row

		return (userId, sessionId)

	def strongestVerify(self, userId, sessionId, log, epochKey, entityKey, lastDigest, EPOCH_WINDOW_SIZE = Logger.Logger.EPOCH_WINDOW_SIZE):
		''' Walks the log chain and epoch chain for verification, and computes the 
		entity digests at every epoch cycle for comparison to check with
		the end result. Not publicly verifiable, and requires the initial epoch and entity keys.
		'''
		ctChain = []
		sha3 = Keccak.Keccak()

		# It is assumed that we would get this initial key from the trusted server...
		# This verification scheme is not possible without the epoch key...
		lastEpochDigest = hmac.new(epochKey, "0", hashlib.sha512).hexdigest()

		# Check to see if we even have anything to verify
		if not ((userId, sessionId) in log):
			return None
		else:
			# Handle the base of the chain
			first = log[(userId, sessionId)][0]
			firstPayload = str(userId) + str(sessionId) + str(0) + str(first[3]) + str(0)

			# Check the hash chain first
			xi = sha3.Keccak((len(bytes(firstPayload)), firstPayload.encode("hex")))
			computedV = sha3.Keccak((len(xi), xi))
			assert(xi == first[4])

			# Check the epoch chain next
			yi = hmac.new(epochKey, lastEpochDigest.encode("hex") + first[4].encode("hex"), hashlib.sha512).hexdigest()
			assert(yi == first[5])

			# Compute the first part of the entity chain now
			lastEntityDigest = hmac.new(entityKey, xi, hashlib.sha512).hexdigest()
			entityKey = hmac.new(entityKey, "some constant value", hashlib.sha512).hexdigest() 

			# Append the first message.
			ctChain.append(first[3])

			# Walk the chain and make sure we can verify it...
			for i in range(1, len(log[(userId, sessionId)])):
				first = log[(userId, sessionId)][i]

				# Store the message
				firstMessage = first[3] # the message
				ctChain.append(firstMessage)

				# The other data...
				currentHash = first[4] # the hash
				previousHash = log[(userId, sessionId)][i - 1][4]
				
				# Verify that the first entry is correct
				firstPayload =  str(userId) + str(0) + str(i) + str(firstMessage) + str(previousHash)
				firstComputedHash = sha3.Keccak((len(bytes(firstPayload)), firstPayload.encode("hex")))
				assert(currentHash == firstComputedHash)

				# Check the epoch chain to see if we need to cycle
				if ((i % EPOCH_WINDOW_SIZE) == 0):
					# Update the epoch key
					currKey = epochKey
					newKey = sha3.Keccak((len(bytes(currKey)), currKey.encode("hex")))
					epochKey = newKey

					# Pull the last hash block
					length = len(log[(userId, sessionId)])
					lastHash = log[(userId, sessionId)][i - 1][4] 

					# Form the epoch block hash payload
					payload = str(lastEpochDigest) + str(lastHash)
					lastEpochDigest = hmac.new(newKey, payload, hashlib.sha512).hexdigest()

				# Compute the epoch chain value
				yi = hmac.new(epochKey, lastEpochDigest.encode("hex") + first[4].encode("hex"), hashlib.sha512).hexdigest()
				assert(yi == first[5])

				# Compute the first part of the entity chain now
				lastEntityDigest = hmac.new(entityKey, first[4], hashlib.sha512).hexdigest()
				entityKey = hmac.new(entityKey, "some constant value", hashlib.sha512).hexdigest() 

			assert(lastEntityDigest == lastDigest)

			return ctChain

	def weakVerify(self, userId, sessionId, log, epochKey, entityKey, EPOCH_WINDOW_SIZE):
		''' Only walks the log chain for verification.
		'''
		ctChain = []

		# Make sure we have something to verify first...
		if not ((userId, sessionId) in log):
			return None
		else:
			# Handle the base of the chain
			first = log[(userId, sessionId)][0]
			firstPayload = str(userId) + str(sessionId) + str(0) + str(first[3]) + str(0)

			digest = sha3.Keccak((len(bytes(firstPayload)), firstPayload.encode("hex")))
			assert(digest == first[4])

			# Append the first message.
			ctChain.append(first[3])

			# Walk the chain and make sure we can verify it...
			for i in range(1, len(log[(userId, sessionId)])):
				first = log[(userId, sessionId)][i]

				# Store the message
				firstMessage = first[3] # the message
				ctChain.append(firstMessage)

				# The other data...
				currentHash = first[4] # the hash
				previousHash = log[(userId, sessionId)][i - 1][4]
				
				# Verify that the first entry is correct
				print(i)
				firstPayload =  str(userId) + str(0) + str(i) + str(firstMessage) + str(previousHash)
				firstComputedHash = sha3.Keccak((len(bytes(firstPayload)), firstPayload.encode("hex")))
				assert(currentHash == firstComputedHash)

			return ctChain
		
def main():
	''' The crawler thread test (watch it go at runtime).
	'''
	crawler = VerifyCrawler("/Users/caw/Projects/PrivateProjects/LoggingSystem/src/DatabaseModule/log.db")
	crawler.run()

if (__name__ == '__main__'):
	main()
