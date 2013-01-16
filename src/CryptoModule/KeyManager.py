'''
File: KeyManager.py
Author: Christopher A. Wood, caw4567@rit.edu
'''

from EncryptionModule import EncryptionModule

class KeyManager:
	''' The key manager that is used to hold onto the master/public keys for
	the various EncryptionModule.
	'''

	def __init__(self):
		''' Create the list to hold the ciphers for encryption.
		'''
		self.cipherList = []

	def addCipher(self, cipher):
		''' Add a new cipher to the list to be managed.
		'''
		self.cipherList.append(cipher)

	def removeCipher(self, cipher):
		raise Exception("Not implemented.")

	def resetKeys(self, keyMap):
		''' Reset the master/public keys for all of the ciphers that are being used by 
		the system right now.
		'''
		for c in self.cipherQueue:
			c.setKeys(keyMap['mk'], keyMap['pk'])

	
