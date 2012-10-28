'''
File: PolicyManager.py
Author: Christopher Wood, caw4567@rit.edu
'''

import PolicyEngine

import sys
sys.path.append("../LoggerModule")
sys.path.append("../Common")
sys.path.append("../DatabaseModule")

import LogEntry
import EventInformation
import DBShim

from pykka.actor import ThreadingActor

class PolicyManager(ThreadingActor):
	'''
	The policy engine that will use event, source, and requestor to generate keys.
	'''

	def on_start(self):
		'''
		Create the context information for this policy engine.
		'''
		self.engine = PolicyEngine.PolicyEngine()

		# Define the event lookup table here - this is where all of the supported events are defined
		self.eventMap = {}
		self.eventMap['eventA'] = self.engine.handleEventA
		self.eventMap['eventB'] = self.engine.handleEventB

		# Create the DB shim to connect to the user attribute database
		self.shim = DBShim.DBShim("/Users/caw/Projects/PrivateProjects/LoggingSystem/src/DatabaseModule/users.sqlite") 

		print("PolicyManager actor started.")

	def on_receive(self, message):
		if message.get('command') == 'policy':
			return self.generatePolicy(message['payload'])
		elif message.get('command') == 'attributes':
			return self.generateAttributes(message['payload'])

	def generatePolicy(self, payload):
		'''
		Generate the policy for a specific user by reaching out the user attribute database
		for this user's attributes.
		'''
		entry = LogEntry.LogEntry(jsonString = payload)
		conj = ''
		try:
			attrs = self.userAttributes(str(entry.user))
			print(attrs)
			conj = '('
			for i in range(len(attrs) - 1):
				conj = conj + str(attrs[i]).lower() + ' and '
			conj = conj + str(attrs[len(attrs) - 1].lower() + ')')	
		except:
			print("Error: invalid result from users database")
		return conj

	def generateAttributes(self, eventInfo):
		print(user)
		return [] # need to reach out to the policyengine to see what's supported.
		# Use LUT (self.eventMap) to determine if the specified event is supported...

		# everything is a string, so we need to go out to the database for this information and then
		# invoke the correct event handler 

	def userAttributes(self, userId):
		'''
		Reach out to the user database for their attributes
		'''
		result = self.shim.executeQuery("users", "id", str(userId))	
		return (result[0]["attributes"].split(','))

