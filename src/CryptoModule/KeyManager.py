'''
File: KeyManager.py
Author: Christopher A. Wood, caw4567@rit.edu
'''

from EncryptionModule import EncryptionModule
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07 

class KeyManager:
	''' The key manager that is used to hold onto the master/public keys for
	the various EncryptionModule.
	'''

	def __init__(self):
		''' Create the initial master key and then the list to hold the ciphers for encryption.
		'''
		self.groupObj = PairingGroup('SS512')
		self.cpabe = CPabe_BSW07(self.groupObj)
		(self.public, self.master) = self.cpabe.setup()

		# Cipher list...
		self.cipherList = []

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
		for c in self.cipherQueue:
			c.setKeys(keyMap['mk'], keyMap['pk'])

	
