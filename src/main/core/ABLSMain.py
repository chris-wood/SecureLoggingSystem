'''
File: ABLSMain.py
Author: Christopher Wood, caw4567@rit.edu
Usage:

	python ABLSMain.py [-l] [-a] [-v]

'''

import sys
import time
import threading
import traceback
from datetime import datetime
import uuid
import hashlib
import logging
import pika

# Build the system path
sys.path.append("./LoggerModule/")
sys.path.append("./PolicyEngineModule/")
sys.path.append("./AuditModule/")
sys.path.append("./Common")
sys.path.append("./DatabaseModule")
sys.path.append("./VerifyModule")
sys.path.append("./CryptoModule")
sys.path.append("./core/LoggerModule/")
sys.path.append("./core/PolicyEngineModule/")
sys.path.append("./core/AuditModule/")
sys.path.append("./core/Common")
sys.path.append("./core/DatabaseModule")
sys.path.append("./core/VerifyModule")
sys.path.append("./core/CryptoModule")
from Logger import Logger
from LogProxy import LogProxy
from LogCollector import LogCollector
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

def loadConfig(configFile = "abls.conf"):
	''' Message to load the configuration file.
	'''
	# Configure the map...
	params = {"SERVER_HOST" : "", "LOG_PORT" : 0, "AUDIT_PORT" : 0, "LOG_DB" : "", "KEY_DB" : "", "USER_DB" : "", "AUDIT_USER_DB" : ""}

	# Load the config file parameters
	f = open(configFile, "r")
	lines = f.readlines()

	# Parse each one
	for line in lines:
		parts = line.split("=")
		#print(parts)
		if ("abls_host" in line):
			params["SERVER_HOST"] = parts[1].rstrip().strip()
		if ("abls_logger_port" in line):
			params["LOG_PORT"] = int(parts[1].rstrip().strip())
		if ("abls_audit_port" in line):
			params["AUDIT_PORT"] = int(parts[1].rstrip().strip())
		if ("location.db.log" in line):
			params["LOG_DB"] = parts[1].rstrip().strip()
		if ("location.db.key" in line):
			params["KEY_DB"] = parts[1].rstrip().strip()
		if ("location.db.users" in line):
			params["USER_DB"] = parts[1].rstrip().strip()
		if ("location.db.audit_users" in line):
			params["AUDIT_USER_DB"] = parts[1].rstrip().strip()
	return params

def startABLS(startAll = False):
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

	# Create the global configuration object...
	params = loadConfig()

	# See if they even started anything
	if (audit == log == verify == False and not startAll):
		printUsage()
		sys.exit(0)

	# Create the master key manager...
	keyMgr = KeyManager()

	# Start whatever services are specified by the user...
	if (log or startAll):
		print("Starting the log service on port " + str(params["LOG_PORT"]))
		collector = LogCollector(params, keyMgr)
		logger = Logger(params, keyMgr, collector).start()
		print("Starting the log proxy")
		logProxy = LogProxy(params, keyMgr, collector).start()
	if (audit):
		print("Starting the audit service on port " + str(params["AUDIT_PORT"]))
		auditProxy = AuditProxy(params, keyMgr).start()
	if (verify):
		print("Starting the verify service")
		verifier = VerifyCrawler(1, params["LOG_DB"], params["KEY_DB"], keyMgr).start()

	'''
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
	'''

if (__name__ == '__main__'):
	startABLS(False, False, False)