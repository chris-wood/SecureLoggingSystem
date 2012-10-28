'''
File: newchainer.py
Author: Christopher Wood, caw4567@rit.edu
Usage:
	python newchainer.py
'''

from __future__ import print_function
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.integergroup import IntegerGroup
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc, Input, Output
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07 # Load the CP-ABE scheme as defined by Bethencourt in 2007 paper
from charm.toolbox.symcrypto import AuthenticatedCryptoAbstraction # for symmetric crypto
from charm.core.math.pairing import hashPair as sha1 # to hash the element for symmetric key (is it worthwhile to switch to a different hash function?)

import aa_test
import time
import operator

# For timing...
from datetime import datetime
from timeit import Timer

import sys
sys.path.append("../Common")
import Keccak # The SHA-3 candidate, of course

# For HMAC
import hashlib, hmac

# type annotations
pk_t = { 'g':G1, 'g2':G2, 'h':G1, 'f':G1, 'e_gg_alpha':GT }
mk_t = {'beta':ZR, 'g2_alpha':G2 }
sk_t = { 'D':G2, 'Dj':G2, 'Djp':G1, 'S':unicode } 
ct_t = { 'C_tilde':GT, 'C':G1, 'Cy':G1, 'Cyp':G2, 'policy':unicode, 'attributes':unicode }

# The local "databases"
log = {} # key is (user, session)
epoch = {} # key is (user, session)
entity = {} # key is (user, session)
# CAW: TODO: make use of the entity to encrypt the epoch chain at every cycle

# Epoch key list
epochKey = {} # key is (user, session)
entityKey = {} # key is (user, session)

# Hash function...
sha3 = Keccak.Keccak()

# The epoch window size
EPOCH_WINDOW_SIZE = 10 # keep it simple...

# Experiment setup:
# - Time log generation process (both with and without epoch rollover)
# - Vary the epoch window and record effects

def strongestVerify(userId, sessionId):
	'''
	Walks the log chain and epoch chain for verification, and computes the 
	entity digests at every epoch cycle for comparison to check with
	the end result. Not publicly verifiable, and requires the initial epoch and entity keys.
	'''
	ctChain = []

	# It is assumed that we would get this initial key from the trusted server...
	# This verification scheme is not possible without the epoch key...
	epochKey = hmac.new("\0bx" * 20, "0", hashlib.sha512).hexdigest()
	lastEpochDigest = hmac.new(epochKey, "0", hashlib.sha512).hexdigest()

	# It is assumed that we would get the entity key from the trusted server...
	# This verification scheme is not possible without the entity key...
	entityKey = hmac.new("\FFx" * 20, "0", hashlib.sha512).hexdigest()
	#lastEntityDigest = hmac.new(entityKey, xi, hashlib.sha512).hexdigest()
	#entityKey = hmac.new(entityKey, "some constant value", hashlib.sha512).hexdigest() # update the keys

	if not ((userId, sessionId) in log):
		#print("Error: nothing to verify")
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
		entityKey = hmac.new(entityKey, "some constant value", hashlib.sha512).hexdigest() # update thate newKey

		# Continue onwards...
		#print("Base chain verification passed!")

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
			#firstCheck = first[5]
			previousHash = log[(userId, sessionId)][i - 1][4]
			
			# Verify that the first entry is correct
			#print(i)
			firstPayload =  str(userId) + str(0) + str(i) + str(firstMessage) + str(previousHash)
			#payload = str(userId) + str(0) + str(epochLength) + str(message) + str(lastHash)
			firstComputedHash = sha3.Keccak((len(bytes(firstPayload)), firstPayload.encode("hex")))

			# Check the hash chain
			#print("stored hash: " + str(currentHash))
			#print("computed hash: " + str(firstComputedHash))
			assert(currentHash == firstComputedHash)

			# Check the epoch chain to see if we need to cycle
			if ((i % EPOCH_WINDOW_SIZE) == 0):
				# update key and save the last digest
				# Update the epoch key
				currKey = epochKey
				newKey = sha3.Keccak((len(bytes(currKey)), currKey.encode("hex")))
				epochKey = newKey

				# Pull the last hash block
				length = len(log[(userId, sessionId)])
				lastHash = log[(userId, sessionId)][i - 1][4] # hash of the log entry is the 4th element in the tuple...

				# Form the epoch block hash payload
				payload = str(lastEpochDigest) + str(lastHash)
				#print("About to compute epoch hash with key: " + str(newKey)) # debug
				lastEpochDigest = hmac.new(newKey, payload, hashlib.sha512).hexdigest()

			# Compute the epoch chain value
			yi = hmac.new(epochKey, lastEpochDigest.encode("hex") + first[4].encode("hex"), hashlib.sha512).hexdigest()
			assert(yi == first[5])

			# Compute the first part of the entity chain now
			lastEntityDigest = hmac.new(entityKey, first[4], hashlib.sha512).hexdigest()
			entityKey = hmac.new(entityKey, "some constant value", hashlib.sha512).hexdigest() # update thate newKey

		assert(lastEntityDigest == entity[(userId, sessionId)])

		#print("Verification passed!")
		return ctChain

def strongVerify(userId, sessionId):
	'''
	Walks the log chain and epoch chain for verification.
	Not publicly verifiable, and requires the initial epoch and entity keys.
	'''
	ctChain = []

	# It is assumed that we would get this initial key from the trusted server...
	# This verification scheme is not possible without the epoch key...
	epochKey = hmac.new("\0bx" * 20, "0", hashlib.sha512).hexdigest()
	lastEpochDigest = hmac.new(epochKey, "0", hashlib.sha512).hexdigest()

	if not ((userId, sessionId) in log):
		print("Error: nothing to verify")
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

		# Continue onwards...
		print("Base chain verification passed!")

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
			#firstCheck = first[5]
			previousHash = log[(userId, sessionId)][i - 1][4]
			
			# Verify that the first entry is correct
			print(i)
			firstPayload =  str(userId) + str(0) + str(i) + str(firstMessage) + str(previousHash)
			#payload = str(userId) + str(0) + str(epochLength) + str(message) + str(lastHash)
			firstComputedHash = sha3.Keccak((len(bytes(firstPayload)), firstPayload.encode("hex")))

			# Check the hash chain
			print("stored hash: " + str(currentHash))
			print("computed hash: " + str(firstComputedHash))
			assert(currentHash == firstComputedHash)

			# Check the epoch chain to see if we need to cycle
			if ((i % EPOCH_WINDOW_SIZE) == 0):
				# update key and save the last digest
				# Update the epoch key
				currKey = epochKey
				newKey = sha3.Keccak((len(bytes(currKey)), currKey.encode("hex")))
				epochKey = newKey

				# Pull the last hash block
				length = len(log[(userId, sessionId)])
				lastHash = log[(userId, sessionId)][i - 1][4] # hash of the log entry is the 4th element in the tuple...

				# Form the epoch block hash payload
				payload = str(lastEpochDigest) + str(lastHash)
				#print("About to compute epoch hash with key: " + str(newKey)) # debug
				lastEpochDigest = hmac.new(newKey, payload, hashlib.sha512).hexdigest()

			# Compute the epoch chain value
			yi = hmac.new(epochKey, lastEpochDigest.encode("hex") + first[4].encode("hex"), hashlib.sha512).hexdigest()
			assert(yi == first[5])

		print("Verification passed!")
		return ctChain

def weakVerify(userId, sessionId):
	'''
	Only walks the log chain for verification
	'''
	ctChain = []
	if not ((userId, sessionId) in log):
		#print("Error: nothing to verify")
		return None
	else:
		# Handle the base of the chain
		first = log[(userId, sessionId)][0]
		firstPayload = str(userId) + str(sessionId) + str(0) + str(first[3]) + str(0)

		digest = sha3.Keccak((len(bytes(firstPayload)), firstPayload.encode("hex")))
		#computedV = sha3.Keccak((len(digest), digest))
		assert(digest == first[4])
		#print("Base chain verification passed!")

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
			#firstCheck = first[5]
			previousHash = log[(userId, sessionId)][i - 1][4]
			
			# Verify that the first entry is correct
			#print(i)
			firstPayload =  str(userId) + str(0) + str(i) + str(firstMessage) + str(previousHash)
			#payload = str(userId) + str(0) + str(epochLength) + str(message) + str(lastHash)
			firstComputedHash = sha3.Keccak((len(bytes(firstPayload)), firstPayload.encode("hex")))
			#print("stored hash: " + str(currentHash))
			#print("computed hash: " + str(firstComputedHash))
			assert(currentHash == firstComputedHash)
			#firstComputedCheck = sha3.Keccak((len(firstComputedHash), firstComputedHash))
			#assert(firstComputedCheck == firstCheck)

		#print("Verification passed!")
		return ctChain


def addNewEvent(userId, sessionId, message):
	'''
	Construct a new event to add to the log. It is assumed the epoch key is 
	already initialized before this happens.
	'''
	global log
	global epochKey
	global epoch

	# Some definitions
	xi = None
	yi = None
	zi = None
	payload = ""
	lastEpochDigest = None

	if not (userId, sessionId) in log:
		log[(userId, sessionId)] = []
		epoch[(userId, sessionId)] = []

		# Create the initial epoch block
		currKey = epochKey[(userId, sessionId)]
		lastEpochDigest = hmac.new(currKey, "0", hashlib.sha512).hexdigest()
		epoch[(userId, sessionId)].append(lastEpochDigest)

		# Create the entry payload
		payload = str(userId) + str(sessionId) + str(0) + str(message) + str(0) # hash of this entry is (user, session, epoch, msg, previous == 0)
	else:
		# Need to do checks for the epoch...
		length = len(log[(userId, sessionId)])
		if (length % EPOCH_WINDOW_SIZE) == 0: # We have cycled around... create an epoch checkpoint and save it

			# Update the epoch key
			currKey = epochKey[(userId, sessionId)]
			newKey = sha3.Keccak((len(bytes(currKey)), currKey.encode("hex")))
			epochKey[(userId, sessionId)] = newKey

			# Pull the last epoch block
			length = len(epoch[(userId, sessionId)])
			lastEpoch = epoch[(userId, sessionId)][length - 1]

			# Pull the last hash block
			length = len(log[(userId, sessionId)])
			lastHash = log[(userId, sessionId)][length - 1][4] # hash of the log entry is the 4th element in the tuple...

			# Form the epoch block hash payload
			payload = str(lastEpoch) + str(lastHash)
			#print("About to compute epoch hash with key: " + str(newKey)) # debug
			digest = hmac.new(newKey, payload, hashlib.sha512).hexdigest()

			# Store the epoch digest...
			epoch[(userId, sessionId)].append(digest)

		# Now, generate the payload for this log entry
		logLength = len(log[(userId, sessionId)])
		lastHash = log[(userId, sessionId)][logLength - 1][4] # hash of the log entry is the 4th element in the tuple... 
		#print("epoch length: " + str(logLength))
		payload = str(userId) + str(0) + str(logLength) + str(message) + str(lastHash)

	# Now hash the hash chain entry... But first, build up the data that's needed
	currKey = epochKey[(userId, sessionId)]
	epochLength = len(epoch[(userId, sessionId)])
	lastEpoch = epoch[(userId, sessionId)][epochLength - 1]

	# Here are the elements
	xi = sha3.Keccak((len(bytes(payload)), payload.encode("hex"))) # not authentication
	#yi = hmac.new(currKey, xi.encode("hex"), hashlib.sha512).hexdigest() # not authenticated
	yi = hmac.new(currKey, lastEpoch.encode("hex") + xi.encode("hex"), hashlib.sha512).hexdigest()
	#zi = hmac.new(currKey, lastEpoch.encode("hex") + yi.encode("hex"), hashlib.sha512).hexdigest()

	# Store the latest entity digest
	currEntityKey = entityKey[(userId, sessionId)]
	lastEntityDigest = hmac.new(currEntityKey, xi, hashlib.sha512).hexdigest()
	entity[(userId, sessionId)] = lastEntityDigest # update the stamp
	entityKey[(userId, sessionId)] = hmac.new(currEntityKey, "some constant value", hashlib.sha512).hexdigest() # update the keys

	# Store the elements now
	log[(userId, sessionId)].append((userId, sessionId, epochLength, message, xi, yi))
	return log[(userId, sessionId)][len(log[(userId, sessionId)]) - 1] 

	#firstEncoded = payload.encode("hex")
	#test = sha3.Keccak((len(bytes(payload)), payload.encode("hex")))
	#assert(yi == test) # just for peace of mind... the Keccak module keeps no internal state
	#vi = sha3.Keccak((len(yi), yi))
	#log[(userId, eventId)].append((userId, eventId, message, yi, vi)) 

def timestampMilli(msg, start, end):
	print(msg + str((end - start) * 1000) + "ms")

def timestampMicro(msg, start, end):
	print(msg + str((end - start) * 1000000) + "us")

# The main driver for the hash chain generator
def main():
	# Simple sha3 test
	digest = sha3.Keccak((len(bytes("HELLO,WORLD")), "HELLO,WORLD".encode("hex")))
	#print("Did it work? " + str(digest))

	# The encryption module
	aa = aa_test.AttributeAuthority()

	# Create some users with fixed attributes to start
	userA = aa_test.User(1, ['ONE', 'TWO', 'THREE'])
	userB = aa_test.User(2, ['ONE', 'TWO'])
	userC = aa_test.User(3, ['ONE'])

	# Generate some encrypted messages...
	skA = aa.generateUserKey(userA.attrs)
	skB = aa.generateUserKey(userB.attrs)
	skC = aa.generateUserKey(userC.attrs)

	# Some dummy event IDs
	EVENTA = 0
	EVENTB = 1

	# The policy engine
	engine = aa_test.PolicyEngine()

	# Some events
	eventInfo1 = aa_test.EventInformation(userA, userA, 0)
	eventInfo2 = aa_test.EventInformation(userA, userB, 0)
	eventInfo3 = aa_test.EventInformation(userA, userC, 0)

	# Set the initial entity key...
	entityKey[(userA.id, 0)] = hmac.new("\FFx" * 20, "0", hashlib.sha512).hexdigest()
	print("Initial entity key: " + str(entityKey[(userA.id, 0)]))

	# Set the initial epoch key...
	epochKey[(userA.id, 0)] = hmac.new("\0bx" * 20, "0", hashlib.sha512).hexdigest()
	print("Initial epoch key: " + str(epochKey[(userA.id, 0)]))

	# Insert the first log item
	start = time.time()
	m1 = aa.encrypt("message 1", engine.generateEventAPolicy(userA))
	end = time.time()
	timestampMilli("Encryption time", start, end)

	# Generate timing data for encryption using the specified CPABE params
	# Timing code for encryption
	'''
	with open("times.csv", 'w') as f:
		for i in range(1, 100):
			start = time.time()
			for j in range(0, i):
				aa.encrypt("message 1", engine.generateEventAPolicy(userA))
			end = time.time()
			f.write(str(i) + "," + str((end - start) * 1000) + "\n")
			#timestampMilli("Encryption time", start, end)
	'''

	'''
	# Timing code for hash generation 
	with open("times.csv", 'w') as f:
		for i in range(1, 100):
			start = time.time()
			for j in range(0, i):
				m1 = aa.encrypt("message 1", engine.generateEventAPolicy(userA))
				addNewEvent(userA.id, 0, m1)
			end = time.time()
			f.write(str(i) + "," + str((end - start) * 1000) + "\n")
	'''
	
	
	# So it works... now append more and more messages (make sure we hit the epoch window limit)
	'''
	start = time.time()
	m2 = aa.encrypt("message 2", engine.generateEventAPolicy(userA))
	addNewEvent(userA.id, 0, m2)
	m3 = aa.encrypt("message 3", engine.generateEventAPolicy(userA))
	addNewEvent(userA.id, 0, m3)
	m4 = aa.encrypt("message 4", engine.generateEventAPolicy(userA))
	addNewEvent(userA.id, 0, m4)
	m5 = aa.encrypt("message 5", engine.generateEventAPolicy(userA))
	addNewEvent(userA.id, 0, m5)
	m6 = aa.encrypt("message 6", engine.generateEventAPolicy(userA))
	addNewEvent(userA.id, 0, m6)
	m7 = aa.encrypt("message 7", engine.generateEventAPolicy(userA))
	addNewEvent(userA.id, 0, m7)
	m8 = aa.encrypt("message 8", engine.generateEventAPolicy(userA))
	addNewEvent(userA.id, 0, m8)
	m9 = aa.encrypt("message 9", engine.generateEventAPolicy(userA))
	addNewEvent(userA.id, 0, m9)
	end = time.time()
	#print("Initial entry time: " + str((end - start) * 1000) + "ms")
	timestampMilli("After 8 log entries created and inserted: ", start, end)
	'''

	# Verify the chain now (and then try to decrypt)
	'''
	with open("times.csv", 'w') as f:
		for i in range(1, 100):
			for j in range(0, i):
				addNewEvent(userA.id, 0, m1)
			start = time.time()
			ctChain = strongestVerify(userA.id, 0)
			end = time.time()
			f.write(str(i) + "," + str((end - start) * 1000) + "\n")
	'''

	'''
	ctChain = weakVerify(userA.id, 0)
	if (ctChain != None):
		print("Attempting message chain decryption...")
		for cti in ctChain:
			tempAttribtues = engine.handleEventB(eventInfo1)
			key = aa.generateUserKey(tempAttribtues)
			(success, dec) = aa.decrypt(key, cti)
			print(dec)

	# Now try the stronger versions of verification
	strongVerify(userA.id, 0)
	strongestVerify(userA.id, 0)
	'''


# Run the tests...
if (__name__ == '__main__'):
	main()