'''
File: VerifyCrawler.py
Author: Christopher A. Wood, caw4567@rit.edu
'''

import socket
import time
import threading
import struct
import string
import logging # Python logging module

# Our own stuff
import sys
sys.path.append("../DatabaseModule")
sys.path.append("../CryptoModule")
from DBShim import DBShim
import Logger
from EncryptionModule import EncryptionModule

# test...
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.core.engine.util import objectToBytes,bytesToObject
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

	def __init__(self, vid, logServer, keyServer, keyMgr):
		''' Constructor that stores the log server information.
		'''
		threading.Thread.__init__(self)
		self.id = vid
		self.logServer = logServer
		self.keyServer = keyServer
		self.running = True

		# Build the encryption module
		self.keyMgr = keyMgr
		self.encryptionModule = EncryptionModule(keyMgr) # pass along the key manager reference

		# Generate the used entry bucket
		self.usedBin = {}
		self.MAX_TRIES = 10 # This can (and should) be configured by experimentation.

	def run(self):
		''' The main thread loop for this verifier.
		'''
		# Create the shim
		self.logShim = DBShim(self.logServer, self.keyMgr)
		self.keyShim = DBShim(self.keyServer, self.keyMgr)

		# Run the crawler loop indefinitely...
		while self.running:
			print("Verifier " + str(self.id) + " is trying to grab a user session to verify...")
			(userId, sessionId) = self.selectRow()
			# Check to see if we found some valid data...
			if (userId != -1 and sessionId != -1):
				# Query the keys from the database
				print("Verifying: " + str(userId) + " - " + str(sessionId))
				valueMap = {"userId" : userId, "sessionId" : sessionId}
				epochKey = self.keyShim.executeMultiQuery("initialEpochKey", valueMap, ("userId", "sessionId"))
				key1 = epochKey[0]["key"]
				entityKey = self.keyShim.executeMultiQuery("initialEntityKey", valueMap, ("userId", "sessionId"))
				key2 = entityKey[0]["key"]

				# Decrypt the keys using the 'verifier' policy
				print("Trying to decrypt")
				sk = self.encryptionModule.generateUserKey(['VERIFIER'])
				k1 = self.encryptionModule.decrypt(sk, key1)[1] # [1] to pull out plaintext, [0] is T/F flag
				k2 = self.encryptionModule.decrypt(sk, key2)[1] # [1] to pull out plaintext, [0] is T/F flag

				# Query the last digest from the database
				print("Decryption successful - continue with the verification process")
				entityDigest = self.logShim.executeMultiQuery("entity", valueMap, ("userId", "sessionId"))
				digest = entityDigest[len(entityDigest) - 1]["digest"]			

				# Query for the log now.
				logResult = self.logShim.executeMultiQuery("log", valueMap, ("userId", "sessionId"))
				log = {}
				log[(userId, sessionId)] = []
				for i in range(0, len(logResult)):
					log[(userId, sessionId)].append([userId, sessionId, logResult[i]["epochId"], logResult[i]["message"], logResult[i]["xhash"], logResult[i]["yhash"]])

				# Verify the data extracted from the database...
				self.strongestVerify(userId, sessionId, log, k1, k2, digest, Logger.Logger.EPOCH_WINDOW_SIZE)

			# Don't hog the system resources
			time.sleep(15)

	def selectRow(self):
		''' Randomly select a row from the database to check with strong verification.
		'''
		userId = sessionId = 0
		
		foundNewRow = False
		tries = 0
		while not foundNewRow:
			result = self.logShim.randomQuery("log")
			if (len(result) > 0):
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
							tk1 = -1
							tk2 = -1

					del self.usedBin[(tk1, tk2)]
					userId = tk1
					sessionId = tk2
					foundNewRow = True # we're going to retry a previous row
			else:
				userId = sessionId = -1
				foundNewRow = True

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
			print("checking x's")
			print(xi)
			print(first[4])
			assert(xi == first[4])

			# Check the epoch chain next
			yi = hmac.new(epochKey, lastEpochDigest.encode("hex") + first[4].encode("hex"), hashlib.sha512).hexdigest()
			print("checking y's")
			print(yi)
			print(first[5])
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
			print("Verification result:")
			print(lastEntityDigest == lastDigest)

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
	raise Exception("The VerifierCrawler must be run within the ABLS context to share the cryptographic keys necessary for verification")
	#crawler = VerifyCrawler(1, "/Users/caw/Projects/SecureLoggingSystem/src/DatabaseModule/log.db", "/Users/caw/Projects/SecureLoggingSystem/src/DatabaseModule/key.db")
	#crawler.run()

if (__name__ == '__main__'):
	main()
