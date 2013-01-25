# Test code for audit automation
# Author: Christopher Wood

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
		self.config = config

class AuditTask(threading.Thread):
	''' The automated audit thread class.
	'''
	def __init__(self, params, keyMgr, rule):
		''' Default constructor.
		'''	
		super(Logger, self).__init__()
		self._stop = threading.Event()
		self.params = params

	def run(self):
		print("TODO: throw in the run code here")

def main():
	params = {"USER_DB" : "/Users/caw/Projects/SecureLoggingSystem/src/v2/user.db", "LOG_DB" : "/Users/caw/Projects/SecureLoggingSystem/src/v2/log.db", "KEY_DB" : "/Users/caw/Projects/SecureLoggingSystem/src/v2/key.db"}
	print(params)
	keyMgr = KeyManager()

	# Create some sample audit tasks

	#AuditTask(params, keyMgr).start()	

if (__name__ == "__main__"):
	main()

