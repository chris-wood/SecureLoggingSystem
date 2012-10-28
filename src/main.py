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

def main():
	'''
	The main entry point into the logging system that initializes everything
	needed to be active at runtime.
	'''
	# Just start the traffic proxy... That will spawn everything else as needed
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
	sys.exit(0);

if (__name__ == '__main__'):
	main()