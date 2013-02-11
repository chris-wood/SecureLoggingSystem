'''
File: KeyManager.py
Author: Christopher A. Wood, caw4567@rit.edu
'''

from EncryptionModule import EncryptionModule
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07 
from charm.core.engine.util import objectToBytes,bytesToObject
import pickle
import os.path

class KeyManager:
	''' The key manager that is used to hold onto the master/public keys for
	the various EncryptionModule.
	'''

	def __init__(self, prepend = "core"):
		''' Create the initial master key and then the list to hold the ciphers for encryption.
		'''
		self.groupObj = PairingGroup('SS512')
		if (os.path.isfile(prepend + '/CryptoModule/pubkey.pkl') and os.path.isfile(prepend + '/CryptoModule/masterkey.pkl')):
			print("Loading the master and public key from the file")
			self.public = bytesToObject(pickle.load(open(prepend + '/CryptoModule/pubkey.pkl', 'rb')), self.groupObj)
			self.master = bytesToObject(pickle.load(open(prepend + '/CryptoModule/masterkey.pkl', 'rb')), self.groupObj)
		else:
			self.cpabe = CPabe_BSW07(self.groupObj)
			(self.public, self.master) = self.cpabe.setup()

			# Persist the keys
			outputPublic = open(prepend + '/CryptoModule/pubkey.pkl', 'wb')
			outputMaster = open(prepend + '/CryptoModule/masterkey.pkl', 'wb')
			pickle.dump(objectToBytes(self.public, self.groupObj), outputPublic)
			pickle.dump(objectToBytes(self.master, self.groupObj), outputMaster)
			outputPublic.close()
			outputMaster.close()

		# Cipher list...
		self.cipherList = []

	def getMasterKey(self):
		''' Return the master key.
		'''
		return objectToBytes(self.master, self.groupObj)

	def getPublicKey(self):
		''' Retrieve the public key.
		'''
		return objectToBytes(self.public, self.groupObj)

	def addCipher(self, cipher):
		''' Add a new cipher to the list to be managed.
		'''
		self.cipherList.append(cipher)
		cipher.setKeys(self.master, self.public)

	def removeCipher(self, cipher):
		raise Exception("Not implemented.")

	def resetKeys(self, keyMap):
		''' Reset the master/public keys for all of the ciphers that are being used by 
		the system right now.
		'''
		self.master = bytesToObject(keyMap['mk'], self.groupObj)
		self.public = bytesToObject(keyMap['pk'], self.groupObj)
		for c in self.cipherQueue:
			c.setKeys(self.master, self.public)

	
