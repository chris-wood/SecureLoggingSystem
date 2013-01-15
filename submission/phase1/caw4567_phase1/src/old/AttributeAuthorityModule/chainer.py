'''
File: chainer.py
Author: Christopher Wood, caw4567@rit.edu
Usage:
	python chainer.py
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

import sys
sys.path.append("../Common")
import Keccak # The SHA-3 candidate, of course

# type annotations
pk_t = { 'g':G1, 'g2':G2, 'h':G1, 'f':G1, 'e_gg_alpha':GT }
mk_t = {'beta':ZR, 'g2_alpha':G2 }
sk_t = { 'D':G2, 'Dj':G2, 'Djp':G1, 'S':unicode } 
ct_t = { 'C_tilde':GT, 'C':G1, 'Cy':G1, 'Cyp':G2, 'policy':unicode, 'attributes':unicode }

# The local "database" - this would obviously be put somewhere else
log = {} # key is (user, event)

sha3 = Keccak.Keccak()

def verify(userId, eventId):
	ctChain = []
	if not ((userId, eventId) in log):
		print("Error: nothing to verify")
		return None
	else:
		# Handle the base of the chain
		first = log[(userId, eventId)][0]
		firstPayload = str(0) + str(first[2]) + str(userId)

		digest = sha3.Keccak((len(bytes(firstPayload)), firstPayload.encode("hex")))
		computedV = sha3.Keccak((len(digest), digest))
		assert(computedV == first[4])
		print("Base chain verification passed!")

		# Append the first message.
		ctChain.append(first[2])

		# Walk the chain and make sure we can verify it...
		for i in range(1, len(log[(userId, eventId)])):
			first = log[(userId, eventId)][i]

			# Store the message
			firstMessage = first[2] # the message
			ctChain.append(firstMessage)

			# The other data...
			firstHash = first[3] # the hash
			firstCheck = first[4]
			previousHash = log[(userId, eventId)][i - 1][3]
			
			# Verify that the first entry is correct
			firstPayload = previousHash + str(firstMessage) + str(userId)
			firstComputedHash = sha3.Keccak((len(bytes(firstPayload)), firstPayload.encode("hex")))
			print("stored hash: " + str(firstHash))
			print("computed hash: " + str(firstComputedHash))
			assert(firstHash == firstComputedHash)
			firstComputedCheck = sha3.Keccak((len(firstComputedHash), firstComputedHash))
			assert(firstComputedCheck == firstCheck)

		print("Verification passed!")
		return ctChain


def addNewEvent(userId, eventId, message):
	yi = None
	payload = ""
	if not ((userId, eventId) in log):
		log[(userId, eventId)] = []
		payload = str(0) + str(message) + str(userId)
	else:
		length = len(log[(userId, eventId)])
		previousHash = log[(userId, eventId)][length - 1][3] # y_{i-1} is the 4th element in the tuple
		payload = previousHash + str(message) + str(userId)

	# Now hash the hash chain entry
	yi = sha3.Keccak((len(bytes(payload)), payload.encode("hex")))
	firstEncoded = payload.encode("hex")
	test = sha3.Keccak((len(bytes(payload)), payload.encode("hex")))
	assert(yi == test) # just for peace of mind... the Keccak module keeps no internal state
	vi = sha3.Keccak((len(yi), yi))
	log[(userId, eventId)].append((userId, eventId, message, yi, vi)) 

	# debug purposes
	return log[(userId, eventId)][len(log[(userId, eventId)]) - 1]

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
	eventInfo1 = aa_test.EventInformation(userA, userA, EVENTA)
	eventInfo2 = aa_test.EventInformation(userA, userB, EVENTA)
	eventInfo3 = aa_test.EventInformation(userA, userC, EVENTA)

	# Insert the first log item
	m1 = aa.encrypt("message 1", engine.generateEventAPolicy(userA))
	addNewEvent(userA.id, EVENTA, m1)

	# So it works... now append more and more messages
	m2 = aa.encrypt("message 2", engine.generateEventAPolicy(userA))
	print(addNewEvent(userA.id, EVENTA, m2))
	m3 = aa.encrypt("message 3", engine.generateEventAPolicy(userA))
	print(addNewEvent(userA.id, EVENTA, m3))
	m4 = aa.encrypt("message 4", engine.generateEventAPolicy(userA))
	print(addNewEvent(userA.id, EVENTA, m4))

	# Verify the chain now (and then try to decrypt)
	ctChain = verify(userA.id, EVENTA)
	if (ctChain != None):
		print("Attempting message chain decryption...")
		for cti in ctChain:
			tempAttribtues = engine.handleEventB(eventInfo1)
			key = aa.generateUserKey(tempAttribtues)
			(success, dec) = aa.decrypt(key, cti)
			print(dec)


# Run the tests...
if (__name__ == '__main__'):
	main()