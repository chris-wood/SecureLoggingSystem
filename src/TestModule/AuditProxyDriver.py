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

# Connection settings
HOST = 'localhost'
PORT = 9999
EventCount = 20

# The socket used in communication
sock = None

def close():
	''' Close the open socket.
	'''
	global sock
	sock.close()
	sys.exit(0)

def test(user, params):
	''' Send some test data to the user.
	'''
	for i in range(0, count):
		sock.write('{"userId":' + str(user) + ',"sessionId":' + str(session) + ',"payload":"' + str(payload) + '"}')
		print('{"userId":' + str(user) + ',"sessionId":' + str(session) + ',"payload":"' + str(payload) + '"}')
		time.sleep(sleep)

def help():
	''' Display the supported commands.
	'''
	print("Supported commands:")
	print("   help or ? - display available commands.")
	print("   quit - quite the test driver")

def handleInput(userInput):
	''' Determine the action to take based on user input.
	'''
	if (userInput == 'help' or userInput == '?'):
		help()
	elif (userInput == 'quit'):
		print("Terminating...")
		close()
	else:
		raise Exception("Invalid command: " + userInput)

def prompt():
	''' Prompt the user to enter a command (if they want).
	'''
	print("-----------------------------------------")
	print("             Audit Proxy Driver          ")
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
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.connect((host, port))
			prompt()
		else:
			print("usage: python AuditProxyDriver.py host port")
	except Exception as e:
		print("[ERROR] " + str(e))

# Let it rip
if __name__ == '__main__':
	main()
