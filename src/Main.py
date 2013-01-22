'''
File: Main.py
Author: Christopher Wood, caw4567@rit.edu
Usage:

	python Main.py [-l] [-a] [-v]

'''

import sys
import time
import threading
import traceback
from datetime import datetime
import uuid
import hashlib

# Build the system path
sys.path.append("./LoggerModule/")
sys.path.append("./PolicyEngineModule/")
sys.path.append("./AuditModule/")
sys.path.append("./Common")
sys.path.append("./DatabaseModule")
sys.path.append("./VerifyModule")
sys.path.append("./CryptoModule")
from LogProxy import LogProxy
from VerifyCrawler import VerifyCrawler
from KeyManager import KeyManager
from AuditProxy import AuditProxy
import DBShim

def help():
	''' Display the available commands to the user.
	'''
	print("NOT IMPLEMENTED YET")

def handleInput(userInput):
	''' Helper function to handle user input.
	'''
	if (userInput == 'help' or userInput == '?'):
		help()

def printUsage():
	''' Print the usage message.
	'''
	print("Usage: python main.py [-l] [-a] [-v]")
	print("   -l -> start the logging service")
	print("   -a -> start the audit service")
	print("   -v -> start the verify service")

def main():
	''' The main entry point into the logging system that initializes everything
	needed to be active at runtime.
	'''	

	# Check to see what services should be enabled on startup.
	audit = False
	log = False
	verify = False
	if (len(sys.argv) >= 2):
		for i in range(1, len(sys.argv)):
			if ("-a" in sys.argv[i]):
				audit = True
			if ("-l" in sys.argv[i]):
				log = True
			if ("-v" in sys.argv[i]):
				verify = True

	# See if they even started anything
	if (audit == log == verify == False):
		printUsage()
		sys.exit(0)

	# Create the global configuration object...


	# Create the master key manager...
	keyMgr = KeyManager()

	# TODO: load from the configuration file...

	# Start whatever services are specified by the user...
	if (log):
		print("Starting the log service")
		logProxy = LogProxy(keyMgr).start()	
	if (audit):
		print("Starting the audit service")
		auditProxy = AuditProxy(keyMgr).start()
	if (verify):
		print("Starting the verify service")
		verifier = VerifyCrawler(1, "/Users/caw/Projects/SecureLoggingSystem/src/DatabaseModule/log.db", "/Users/caw/Projects/SecureLoggingSystem/src/DatabaseModule/key.db", keyMgr).start()

	# Jump into the input-handling loop...
	print("---------------------------")
	print("Type 'help' or '?' for help")
	print("---------------------------")
	userInput = raw_input(">> ")
	handleInput(userInput)
	while (userInput != 'quit'):
		userInput = raw_input(">> ")
		handleInput(userInput)

	# Kill everything
	proxy.kill()
	sys.exit(0);

if (__name__ == '__main__'):
	main()