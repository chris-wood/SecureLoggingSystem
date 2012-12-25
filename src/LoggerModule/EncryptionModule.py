'''
File: EncryptionModule.py
Author: Christopher A. Wood, caw4567@rit.edu
'''

from __future__ import print_function
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.integergroup import IntegerGroup
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc, Input, Output
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07 # Load the CP-ABE scheme as defined by Bethencourt in 2007 paper
from charm.toolbox.symcrypto import AuthenticatedCryptoAbstraction # for symmetric crypto
from charm.core.math.pairing import hashPair as sha1 # to hash the element for symmetric key (is it worthwhile to switch to a different hash function?)

# Type annotations
pk_t = { 'g':G1, 'g2':G2, 'h':G1, 'f':G1, 'e_gg_alpha':GT }
mk_t = {'beta':ZR, 'g2_alpha':G2 }
sk_t = { 'D':G2, 'Dj':G2, 'Djp':G1, 'S':unicode } 
ct_t = { 'C_tilde':GT, 'C':G1, 'Cy':G1, 'Cyp':G2, 'policy':unicode, 'attributes':unicode }

class EncryptionModule:
	''' The encryption class that handles encryption/decryption for data.

	It must reach out to the attribute authority to retrieve the master and public
	key used for encryption and decryption.
	'''

	def __init__(self):
		self.groupObj = PairingGroup('SS512')
		self.cpabe = CPabe_BSW07(self.groupObj)
		(self.public, self.master) = self.cpabe.setup()

	def set(self, master, public):
		''' Set the master and public key for this module. 

		THIS IS NOT SAFE. EXPERIMENTAL USE ONLY.
		'''
		self.master = master
		self.public = public

	def getValues(self):
		''' Retrieve the master and public key pairs.
		'''
		return (self.master, self.public)

	def generateUserKey(self, attributes):
		''' Generate a secret key for a user given their access structure.
		'''
		return self.cpabe.keygen(self.public, self.master, attributes)

	def encrypt(self, plaintext, policy):
		''' Encrypt a block of plaintext using the provided polcy structure. 
		The ciphertext is stored as a dictionary, for now.
		'''
		key = self.groupObj.random(GT)
		c1 = self.cpabe.encrypt(self.public, key, policy)

        # Instantiate a symmetric enc scheme from this key
		cipher = AuthenticatedCryptoAbstraction(sha1(key))
		c2 = cipher.encrypt(plaintext)
		return { 'c1':c1, 'c2':c2 }

	def decrypt(self, sKey, ciphertext):
		''' Decrypt the provided ciphertext sing the secret key. Decryption is only successful if
		the policy embedded in the secret key matches the ciphertext access policy.
		'''
		c1, c2 = ciphertext['c1'], ciphertext['c2']
		success = True

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
