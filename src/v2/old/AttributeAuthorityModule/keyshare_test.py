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

from charm.core.engine.util import objectToBytes, bytesToObject

import pickle
import json

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


# The main driver to test the AA and policy engine ideas (so they can be finalized before implementing in the DJango application)
# The scheme needs to be documented before implemented in the DJango web app
def main():
	aa = AttributeAuthority()
	sk = aa.generateUserKey(['ONE', 'TWO', 'THREE'])

	

# Run the tests...
if (__name__ == '__main__'):
	main()