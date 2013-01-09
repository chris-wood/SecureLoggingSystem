'''
File: main.py
Author: Christopher Wood, caw4567@rit.edu
Usage:

	python main.py

'''

import sys
import time
import threading
import traceback

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
		print("Debug: Clearing the log database")

		# Check to see if we need to clear the table
		# This is specific to SQLite - it needs to be less coupled to SQLite
		shim = DBShim.DBShim("/Users/caw/Projects/SecureLoggingSystem/src/DatabaseModule/log.db")
		tableResults = shim.executeRawQuery("SELECT name FROM sqlite_master WHERE type='table' AND name='log'")
		if (len(tableResults) != 0):
			shim.executeRawQuery("DELETE FROM log")
		tableResults = shim.executeRawQuery("SELECT name FROM sqlite_master WHERE type='table' AND name='entity'")
		if (len(tableResults) != 0):
			shim.executeRawQuery("DELETE FROM entity")
		tableResults = shim.executeRawQuery("SELECT name FROM sqlite_master WHERE type='table' AND name='epoch'")
		if (len(tableResults) != 0):
			shim.executeRawQuery("DELETE FROM epoch")


		# Check to see if we need to clear the table
		# This is specific to SQLite - it needs to be less coupled to SQLite
		shim = DBShim.DBShim("/Users/caw/Projects/SecureLoggingSystem/src/DatabaseModule/users.db")
		tableResults = shim.executeRawQuery("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
		if (len(tableResults) != 0):
			# Delete the contents in the table
			shim.executeRawQuery("DELETE FROM users")
			
			# Re-populate it with dummy users (alice, bob, chris)
			print("Initializing dummy data into the users table")
			shim.insertIntoTable("users", "(userId, name, email, attributes)", (0, "alice", "alice@test.com", "one"))
			shim.insertIntoTable("users", "(userId, name, email, attributes)", (1, "bob", "bob@test.com", "two"))
			shim.insertIntoTable("users", "(userId, name, email, attributes)", (2, "chris", "chris@test.com", "three"))

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
	print("Usage: python main.py [-c] [-s]")
	print("   -c -> clear the Log database")

def main():
	'''
	The main entry point into the logging system that initializes everything
	needed to be active at runtime.
	'''	

	# Check for debug mode (which clears the database and initalizes with some content)
	debugMode = False
	startMode = False
	if (len(sys.argv) >= 2):
		for i in range(1, len(sys.argv)):
			if ("-c" in sys.argv[i]):
				debugMode = True
			if ("-s" in sys.argv[i]):
				startMode = True

	# Bootstrap the system
	bootstrap(debug = debugMode)

	# Just start the traffic proxy... that will spawn everything else as needed
	if (startMode):
		proxy = TrafficProxy.TrafficProxy().start()
		print("---------------------------")
		print("Type 'help' or '?' for help")
		print("---------------------------")
		userInput = raw_input(">> ")
		handleInput(userInput)

		# The user input loop
		while (userInput != 'quit'):
			userInput = raw_input(">> ")
			handleInput(userInput)

		# Kill everything
		proxy.kill()
		sys.exit(0);

if (__name__ == '__main__'):
	main()