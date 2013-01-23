'''
File: LogEntry.py
Author: Christopher A. Wood, caw4567@rit.edu
'''

import json

class LogEntry(object):
	'''
	This class is just a wrapper for log information retrieved from the application.
	'''

	def __init__(self, jsonString = None, userId = None, sessionId = None, payLoad = None):
		'''
		Construct a log entry object from a JSON string retrieved from the client
		'''
		# Parse the string and check its validity (if JSON string was provided)
		if (jsonString != None):
			data = json.loads(jsonString)
			if (len(data) != 3):
				raise Exception("Corrupt JSON string retrieved from client.")
			if not (('userId' in data) and ('sessionId' in data) and ('payload' in data)):
				raise Exception("Corrupt JSON string retrieved from client.")

			# Persist the data
			self.userId = data['userId']
			self.sessionId = data['sessionId']
			self.payload = data['payload']
			self.json = jsonString
		else:
			self.userId = userId
			self.sessionId = sessionId
			self.payload = payload
		
