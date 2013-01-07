'''
File: main.py
Author: Christopher Wood, caw4567@rit.edu
Usage:

	python main.py

'''

import sys
import time
import threading

# Build the system path
sys.path.append("./LoggerModule/")
sys.path.append("./PolicyEngineModule/")
sys.path.append("./Common")
sys.path.append("./DatabaseModule")
import TrafficProxy
import DBShim

def bootstrap(debug = True):
	''' Bootstrap the database from the database evolution file.
	'''
	# Wipe the data if we're in debug mode
	if (debug == True):
		print("Clearing the log database")

		# Check to see if we need to clear the table
		# This is specific to SQLite - it needs to be less coupled to SQLite
		shim = DBShim.DBShim("/Users/caw/Projects/PrivateProjects/LoggingSystem/src/DatabaseModule/log.sqlite")
		tableResults = shim.executeRawQuery("SELECT name FROM sqlite_master WHERE type='table' AND name='Log'")
		if (len(tableResults) != 0):
			shim.executeRawQuery("DELETE * FROM Log")

def help():
	'''
	Display the available commands to the user.
	'''
	print("NOT IMPLEMENTED YET")

def handleInput(userInput):
	'''
	Helper function to handle user input.
	'''
	if (userInput == 'help' or userInput == '?'):
		help()

def printUsage():
	''' Print the usage message.
	'''
	print("Usage: python main.py [-c]")
	print("   -c -> clear the Log database")

def main():
	'''
	The main entry point into the logging system that initializes everything
	needed to be active at runtime.
	'''	

	debugMode = False
	if (len(sys.argv) == 2):
		if ("-c" in sys.argv[1]):
			debugMode = True

	# Bootstrap the system
	bootstrap(debug = debugMode)

	# Just start the traffic proxy... that will spawn everything else as needed
	'''
	proxy = TrafficProxy.TrafficProxy().start()

	# Handle user input now...
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
	'''
	sys.exit(0);

if (__name__ == '__main__'):
	main()