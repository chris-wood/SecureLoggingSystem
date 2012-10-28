'''
File: aa.py
Author: Christopher Wood, caw4567@rit.edu
Usage:
	python aa_test.py
'''

from __future__ import print_function
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.integergroup import IntegerGroup
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc, Input, Output
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07 # Load the CP-ABE scheme as defined by Bethencourt in 2007 paper
from charm.toolbox.symcrypto import AuthenticatedCryptoAbstraction # for symmetric crypto
from charm.core.math.pairing import hashPair as sha1 # to hash the element for symmetric key (is it worthwhile to switch to a different hash function?)

# type annotations
pk_t = { 'g':G1, 'g2':G2, 'h':G1, 'f':G1, 'e_gg_alpha':GT }
mk_t = {'beta':ZR, 'g2_alpha':G2 }
sk_t = { 'D':G2, 'Dj':G2, 'Djp':G1, 'S':unicode } 
ct_t = { 'C_tilde':GT, 'C':G1, 'Cy':G1, 'Cyp':G2, 'policy':unicode, 'attributes':unicode }

class AttributeAuthority:
	'''
	The attribtue authority class that encapsulates the master key used to generate
	the single public key and user private keys
	'''

	def __init__(self):
		self.groupObj = PairingGroup('SS512') # MNT224, SS512, MNT159, SS1024
		self.cpabe = CPabe_BSW07(self.groupObj)
		(self.public, self.master) = self.cpabe.setup()
		# later functionality would include a thread that periodically updates the keys when needed

	def set(self, master, public):
		self.master = master
		self.public = public

	def getValues(self):
		return (self.master, self.public)

	def generateUserKey(self, attributes):
		return self.cpabe.keygen(self.public, self.master, attributes)

	def getPublicKey(self):
		return self.public

	def encrypt(self, plaintext, policy):
		#return self.cpabe.encrypt(self.public, plaintext, policy)
		key = self.groupObj.random(GT)
		c1 = self.cpabe.encrypt(self.public, key, policy)

        # instantiate a symmetric enc scheme from this key
		cipher = AuthenticatedCryptoAbstraction(sha1(key))
		c2 = cipher.encrypt(plaintext)
		return { 'c1':c1, 'c2':c2 }

	def decrypt(self, sKey, ciphertext):
		#return self.cpabe.decrypt(self.public, sKey, ciphertext)
		c1, c2 = ciphertext['c1'], ciphertext['c2']
		success = True

		# TODO: we need to supress the print statement that comes out of this guy, to avoid unnecessary events
		try:
			key = self.cpabe.decrypt(self.public, sKey, c1)
			if (key == False):
				success = False
		except: 
			success = False

		# Try to perform the encryption if we were able to recover the key
		plaintext = None
		if (success == True):
			cipher = AuthenticatedCryptoAbstraction(sha1(key))
			plaintext = cipher.decrypt(c2)
		return (success, plaintext)

# Class that wraps up information used in processing of events to determine decryption!
class EventInformation(object):

	# Slots for the instance variables...
	__slots__ = ['sourceUser', 'targetUser', 'eventId']

	def __init__(self, source, target, event):
		#print("interesting...")
		self.sourceUser = source
		self.targetUser = target
		self.eventId = event
		#print(str(event))
		#print(sourceUser)

# The policy engine that will use event, source, and requestor to generate keys
class PolicyEngine(object):

	#aa = AttributeAuthority() # encapsulate the attribute authority access, we can treat this as a -proxy- object too so it's not necessarily contained in the same application

	#def generateUserKey(self, user):
	#	return aa.generateUserKey(user.attrs)

	def generateEventAPolicy(self, user):
		conj = '('
		for i in range(len(user.attrs) - 1):
			conj = conj + str(user.attrs[i]).lower() + ' and '
		conj = conj + str(user.attrs[len(user.attrs) - 1].lower() + ')')
		return conj
		#return '(' + str(user.id) + ')'

	# For event A, we only let the user get access, no exceptions
	#TODO: this should return generate an event of its own and store it in its own database (indicates requests to check events for decryption)
	def handleEventA(self, eventInfo):
		#print(str(eventInfo.targetUser.id) + "," + str(eventInfo.sourceUser.id))
		if (eventInfo.targetUser.id == eventInfo.sourceUser.id):
			return eventInfo.sourceUser.attrs # TODO: WHAT SHOULD THIS RETURN? A STRING OR SET OF ATTRIBUTES?
		else:
			return [] # an invalid policy that would be used to request user attributes

	# For event B, we can let the user and their friends get access, no exceptions
	def handleEventB(self, eventInfo):
		if ((eventInfo.targetUser.id == eventInfo.sourceUser.id) or (eventInfo.sourceUser.isFriendsWith(eventInfo.targetUser))):
			return eventInfo.sourceUser.attrs # let the target share these attributes for a second
		else:
			return []

# Test model object to see if dynamic key generation policy works
class User(object):

	# Instance variables
	__slots__ = ['id', 'attrs', 'friends']

	def __init__(self, uid, attributes):
		self.id = uid
		self.attrs = attributes
		self.friends = []

	def setAttributes(self, attributes):
		self.attrs = attributes

	def addFriend(self, friend):
		try:
			if (self.friends.index(friend.id) < 0):
				self.friends.append(friend.id)
		except:
			self.friends.append(friend.id)

	def removeFriend(self, friend):
		try:
			if (self.friends.index(friend.id) >= 0):
				self.friends.remove(friend.id)
		except:
			i = 0

	def isFriendsWith(self, friend):
		try:
			result = (self.friends.index(friend.id) >= 0)
			return result
		except:
			return False

def testMultipleObjects():
	'''
	Test result: we can use n>1 AA objects and decrypt in the same way... that's good to hear!
	'''
	aa1 = AttributeAuthority()
	aa2 = AttributeAuthority()

	# Overwrite the parameters...
	aa2.set(aa1.getValues()[0], aa1.getValues()[1])

	sk = aa1.generateUserKey(['ONE', 'TWO', 'THREE'])
	msg = "Hello world!"
	ct = aa1.encrypt(msg, '((four or three) and (three or one))')
	(success, recovered) = aa1.decrypt(sk, ct)
	print("Decryption with AA1 successful:", recovered == msg)
	(success2, recovered2) = aa2.decrypt(sk, ct)
	print("Decryption with AA2 (copied params from AA1) successful:", recovered2 == msg)


# The main driver to test the AA and policy engine ideas (so they can be finalized before implementing in the DJango application)
# The scheme needs to be documented before implemented in the DJango web app
def main():
	aa = AttributeAuthority()
	sk = aa.generateUserKey(['ONE', 'TWO', 'THREE'])

	#TODO: there is no encode method implemented... Why not?!
	#msg = groupObj.encode("hello world!")
	msg = "Hello world!"
	ct = aa.encrypt(msg, '((four or three) and (three or one))')

	#print(ct)
	(success, recovered) = aa.decrypt(sk, ct)
	print("Decryption successful:", recovered == msg)
	print("recovered: ", recovered)

	# This means we can very easily generate new private keys for every session!
	newSk = aa.generateUserKey(['ONE', 'TWO', 'THREE'])
	(success, newRecovered) = aa.decrypt(newSk, ct)
	print("new recovered: ", newRecovered)
	print("Are both decryptions the same?: ", recovered == newRecovered == msg)

	# Try a new set of attributes, and see if can decrypt (our attributes still match the policy!)
	testkey2 = aa.generateUserKey(['THREE', 'FOUR']) # this still adheres to the access policy
	(success, rec2) = aa.decrypt(testkey2, ct)
	print("Did a change in attributes work for the same policy?: ", rec2 == newRecovered == msg)

	# Let's violate the access policy and see if it works for us...
	testkey3 = aa.generateUserKey(['DONT', 'WORK']) # this doesn't adhere to the access policy
	(success, rec3) = aa.decrypt(testkey3, ct)
	print("Did a change in attributes work for a bad policy?: ", rec3 == msg)

	# last test to even see if my policy string is correct
	lastCt = aa.encrypt("you got it", '(one and two and three)')
	lastSk = aa.generateUserKey(['ONE', 'TWO', 'THREE'])
	(success, lastDec) = aa.decrypt(lastSk, lastCt)
	print("last chance...")
	print(lastDec)

	#-----------------------------------------------
	print("---------- TESTING DYNAMIC ATTRIBUTE POLICY --------------")
	# Test the policy engine
	engine = PolicyEngine()

	# Create some users with fixed attributes to start
	userA = User(1, ['ONE', 'TWO', 'THREE'])
	userB = User(2, ['ONE', 'TWO'])
	userC = User(3, ['ONE'])

	# Generate some encrypted messages...
	print("USER ATTRIBUTES: ")
	print(userA.attrs)
	skA = aa.generateUserKey(userA.attrs)
	skB = aa.generateUserKey(userB.attrs)
	skC = aa.generateUserKey(userC.attrs)

	# Constants for the different events that are generated by the machine
	EVENTA = 1
	EVENTB = 2

	print ("encrypting policy: " + engine.generateEventAPolicy(userA))
	ct1 = aa.encrypt("user a's message", engine.generateEventAPolicy(userA))

	# Generate some event information (this would be populated by another source that we trust)
	eventInfo1 = EventInformation(userA, userA, EVENTA)
	eventInfo2 = EventInformation(userA, userB, EVENTA)
	eventInfo3 = EventInformation(userA, userC, EVENTA)
	#eventInfo4 = EventInformation(userA, userA, EVENTA)
	#eventInfo5 = EventInformation(userA, userA, EVENTA)

	#debug
	#print(eventInfo1.sourceUser)
	#print(eventInfo1.targetUser)
	#print(eventInfo1.eventId)

	# pass!
	tempAttribtues = engine.handleEventA(eventInfo1)
	key1 = aa.generateUserKey(tempAttribtues)
	print(tempAttribtues)
	(success1, dec1) = aa.decrypt(key1, ct1)
	print("success: " + str((success1 == True)))

	# fail!
	tempAttribtues = engine.handleEventA(eventInfo2)
	key1 = aa.generateUserKey(tempAttribtues)
	print(tempAttribtues)
	(success1, dec1) = aa.decrypt(key1, ct1)
	print("success: " + str((success1 == False)))

	# fail!
	tempAttribtues = engine.handleEventA(eventInfo3)
	key1 = aa.generateUserKey(tempAttribtues)
	print(tempAttribtues)
	(success1, dec1) = aa.decrypt(key1, ct1)
	print("success: " + str((success1 == False)))

	# Now try changing friends and working with event B
	print("----------- CHANGING FRIENDS AND TRYING EVENT B ------------")
	userA.addFriend(userB)
	userA.addFriend(userC)

	# new events...
	eventInfo1 = EventInformation(userA, userA, EVENTB)
	eventInfo2 = EventInformation(userA, userB, EVENTB)
	eventInfo3 = EventInformation(userA, userC, EVENTB)

	tempAttribtues = engine.handleEventB(eventInfo1)
	key1 = aa.generateUserKey(tempAttribtues)
	print(tempAttribtues)
	(success1, dec1) = aa.decrypt(key1, ct1)
	print("success: " + str((success1 == True)))

	tempAttribtues = engine.handleEventB(eventInfo2)
	key1 = aa.generateUserKey(tempAttribtues)
	print(tempAttribtues)
	(success1, dec1) = aa.decrypt(key1, ct1)
	print("success: " + str((success1 == True)))

	tempAttribtues = engine.handleEventB(eventInfo3)
	key1 = aa.generateUserKey(tempAttribtues)
	print(tempAttribtues)
	(success1, dec1) = aa.decrypt(key1, ct1)
	print("success: " + str((success1 == True)))

	# time goes on... and we're not longer friends with user B
	# we remove them from our list so we don't generate the appropriate profile
	userA.removeFriend(userB)
	tempAttribtues = engine.handleEventB(eventInfo2)
	key1 = aa.generateUserKey(tempAttribtues)
	print(tempAttribtues)
	(success1, dec1) = aa.decrypt(key1, ct1)
	print("success: " + str((success1 == False)))

	# Now run the test that goes out and tests multiple objects
	testMultipleObjects()

# Benefit of dynamic policy: access to logs is determine by user attributes that can change over time (they're store in a database)
# TODO: write up this scheme and design the logger tomorrow
# TODO: implement model and logging system offline before integrating into an existing application
# TODO: figure out a way to generate test data for this approach 

# Run the tests...
if (__name__ == '__main__'):
	main()