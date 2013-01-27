'''
File: Auditor.py
Author: Christopher Wood, caw4567@rit.edu
'''

import time
import json
import threading
from DBShim import DBShim
from KeyManager import KeyManager

class AuditRule():
	''' Class that stores the rules for an audit.
	'''
	def __init__(self, config):
		''' The default (and only) constructor.
		'''
		print(config)
		data = json.loads(config)

		# Save the rule information
		self.config = data
		if ("role" in data.keys()):
			self.role = data["role"]
		else:
			self.role = None
		if ("action" in data.keys()):
			self.action = data["action"]
		else:
			self.action = None
		if ("object" in data.keys()):
			self.object = data["object"]
		else:
			self.object = None

class AuditTask(threading.Thread):
	''' The automated audit thread class.
	'''
	def __init__(self, params, keyMgr, rule):
		''' Default constructor.
		'''	
		super(AuditTask, self).__init__()
		self._stop = threading.Event()
		self.params = params
		self.keyMgr = keyMgr
		self.rule = rule

	def run(self):
		logShim = DBShim(self.params["LOG_DB"], self.keyMgr)
		userShim = DBShim(self.params["USER_DB"], self.keyMgr)
		keyShim = DBShim(self.params["KEY_DB"], self.keyMgr)
		while(True):
			print("Audit task trying to verify the rule: " + str(self.rule.config))

			# Parse the audit rule
			if (self.rule.role != None and self.rule.action != None):
				if (self.rule.object == None):
					valueMap = {"action" : self.rule.action}
				else:
					valueMap = {"action" : self.rule.action, "object" : self.rule.object}
					eventResults = logShim.executeMultiQuery("Event", valueMap, [])
					print(eventResults)
					for event in eventResults:
						userId = event["userId"]
						valueMap = {"roleId" : self.rule.role}
						userResults = userShim.executeMultiQuery("UserRole", valueMap, [])
						for user in userResults:
							if (int(user["userId"]) == int(userId)):
								print("Rule violation by user " + str(userId))

			time.sleep(15)

def main():
	params = {"USER_DB" : "/Users/caw/Projects/SecureLoggingSystem/src/v2/user.db", "LOG_DB" : "/Users/caw/Projects/SecureLoggingSystem/src/v2/log.db", "KEY_DB" : "/Users/caw/Projects/SecureLoggingSystem/src/v2/key.db"}
	keyMgr = KeyManager()

	# Create some sample audit tasks for the rules
	# In a real environment, role/action/object would be replaced by their string name
	# Python sqlite library doesn't seem to want to support JOINs... 
	config = '{"role": 2, "action": 3, "object": 1}' 
	rule1 = AuditRule(config)
	task1 = AuditTask(params, keyMgr, rule1).start()

if (__name__ == "__main__"):
	main()

