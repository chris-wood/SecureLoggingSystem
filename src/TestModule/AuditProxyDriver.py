'''
File: AuditProxyDriver.py
Author: Christopher A. Wood, caw4567@rit.edu
Usage:

	python AuditProxyDriver.py host port

'''

import socket
import ssl
import sys
import time
import json
import ssl
import pprint

# The socket used in communication
sock = None
bufferSize = 1024

def close():
	''' Close the open socket.
	'''
	global sock
	sock.close()
	sys.exit(0)

def login(userInput):
	''' Handle the user login part of the protocol.
	'''
	global sock
	global bufferSize

	# Parse the user's input to execute the command
	pieces = userInput.split()
	print(pieces)
	if (len(pieces) == 3): # login username password
		message = '{"command":1,"parameters":"' + str(pieces[1] + "," + pieces[2]) + '"}'
		print("sending: " + message)

		# Follow the log protocol
		sock.send(message)
		response = sock.recv(bufferSize)
		print(response)
	else:
		raise Exception("Error: Invalid login parameters.")

def sendCommand(command, parameters):
	''' Send the command to the server and then return the response
	'''
	message = '{"command":' + str(command) + ',"parameters":"' + str(parameters) + '"}'
	sock.send(message)
	response = sock.recv(bufferSize)
	return response

def help():
	''' Display the supported commands.
	'''
	print("Supported commands:")
	print("   help or ? - display available commands.")
	print("   login USER PASSWORD - login the user")
	print("   quit - quite the test driver")

def handleInput(userInput):
	''' Determine the action to take based on user input.
	'''
	if (userInput == 'help' or userInput == '?'):
		help()
	if ('login' in userInput):
		params = userInput.split()
		print(sendCommand(1, params[1] + "," + params[2]))
	elif ('selectByUser' in userInput):
		params = userInput.split()
		print(sendCommand(1, params[1] + "," + params[2]))
	elif ('selectByUserSession' in userInput):
		params = userInput.split()
		print(sendCommand(1, params[1] + "," + params[2]))
	elif (userInput == 'quit'):
		print("Terminating...")
		close()
	else:
		raise Exception("Invalid command: " + userInput)

def prompt():
	''' Prompt the user to enter a command (if they want).
	'''
	print("-----------------------------------------")
	print("            Audit Proxy Driver           ")
	print("Type 'help' or '?' for available commands")
	print("-----------------------------------------")

	# Handle the first user input.
	userInput = raw_input(">> ")
	try:
		handleInput(userInput)
	except Exception as e:
		print(e)

	# Here's the actual prompt
	while (userInput != 'quit'):
		userInput = raw_input(">> ")
		try: 
			handleInput(userInput)
		except Exception as e:
			print(e)

def main():
	''' The main driver for this test module. Create the secure socket connection
	and the jump into the user input loop.
	'''
	global sock
	try:
		if (len(sys.argv) == 3):
			# Create the socket using the specified host and port
			host = sys.argv[1]
			port = int(sys.argv[2])
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.connect((host, port))
			prompt()
		else:
			print("usage: python AuditProxyDriver.py host port")
	except Exception as e:
		print("[ERROR] " + str(e))

# Let it rip
if __name__ == '__main__':
	main()
