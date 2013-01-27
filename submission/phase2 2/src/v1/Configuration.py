'''
File: Configuration.py
Author: Christopher Wood, caw4567@rit.edu
'''

SERVER_HOST = ""
LOG_PORT = 0
AUDIT_PORT = 0
LOG_DB = ""
KEY_DB = ""
USER_DB = ""
AUDIT_USER_DB = ""

def loadConfig(configFile = "abls.conf"):
	''' Configuration load function.
	'''
	global SERVER_HOST
	global LOG_PORT
	global AUDIT_PORT
	global LOG_DB 
	global KEY_DB 
	global USER_DB 
	global AUDIT_USER_DB 

	# Open the config file
	f = open(configFile, "r")
	lines = f.readlines()

	# Parse each one
	for line in lines:
		parts = line.split("=")
		#print(parts)
		if ("abls_host" in line):
			print("yeah")
			SERVER_HOST = parts[1].rstrip()
		if ("abls_logger_port" in line):
			print()
		if ("abls_audit_port" in line):
			print()
		if ("location.db.log" in line):
			print()
		if ("location.db.key" in line):
			print()
		if ("location.db.users" in line):
			print()
		if ("location.db.audit_users" in line):
			print()
		if ("location.db.policy" in line):
			print()

