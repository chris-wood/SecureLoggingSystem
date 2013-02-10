'''
File: PolicyManager.py
Author: Christopher Wood, caw4567@rit.edu
'''

import logging 
import traceback
import sys
import LogEntry
import DBShim
from pykka.actor import ThreadingActor

class PolicyManager(ThreadingActor):
	''' The policy engine that will use events to generate keys.
	'''

	def __init__(self, params, keyMgr):
		''' Persist the key manager so we can create our database shim.
		'''
		self.keyMgr = keyMgr
		self.params = params

	def on_start(self):
		''' Create the context information for this policy engine.
		'''
		# Create the DB shim to connect to the user attribute database
		self.shim = DBShim.DBShim(self.params["USER_DB"], self.keyMgr)

	def on_receive(self, message):
		''' Handle an incoming message.
		'''
		if message.get('command') == 'policy':
			return self.generatePolicy(message['payload'])
		elif message.get('command') == 'verifyPolicy':
			return self.generateVerifyPolicy(message['payload'])

	def generateVerifyPolicy(self, payload):
		''' Generate the policy for verification data (containing the verify policy and
			the source user ID).
		'''
		#print("PolicyManager: generating verification policy in PolicyManager.")
		entry = LogEntry.LogEntry(jsonString = payload)
		conj = '(verifier or ' + str(entry.userId) + ')'
		#print("PolicyManager: the resulting policy is: " + conj)
		return conj

	def generatePolicy(self, payload):
		''' Generate the policy for a specific user by reaching out the user attribute database
		for this user's attributes.
		'''
		entry = LogEntry.LogEntry(jsonString = payload)
		conj = ''
		try:
			#print("trying the user database")
			attrs = self.userAttributes(str(entry.userId))
			#print("Attributes for user " + str(entry.userId) + ": " + str(attrs))
			conj = '('
			for i in range(len(attrs) - 1):
				conj = conj + str(attrs[i]).lower() + ' and '
			conj = conj + str(attrs[len(attrs) - 1].lower() + ')')
		except:
			print("Error: invalid result from users database")
		return conj

	def userAttributes(self, userId):
		''' Reach out to the user database for their attributes.
		'''
		result = self.shim.executeQuery("User", "userId", userId, False) # userId is not masked in the user table - there's no point, right?
		return (result[0]["attributes"].split(','))

