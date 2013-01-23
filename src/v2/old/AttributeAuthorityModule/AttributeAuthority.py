'''
File: AttributeAuthority.py
Author: Christopher Wood, caw4567@rit.edu
'''

import threading # for our own control flow
import Queue

class AttributeAuthority(threading.Thread):
	'''
	This class is responsible for configuring the CP-ABE parameters
	for encryption and decryption, maintaining access to the AA database
	for the master and private key, and maintaining the list of user attributes.

	Message-passing is used 
	'''

	def __init__(self):
		'''
		Initialize the 
		'''
		self.queue = Queue()

	def run(self):
		print("TODO")
