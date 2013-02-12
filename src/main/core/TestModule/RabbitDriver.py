'''
File: RabbitDriver.py
Author: Christopher A. Wood, caw4567@rit.edu
Usage:

	python LogProxyDriver.py host port

'''

import sys
import pika

def test(user, session, payload, count, sleep = 0):
	''' Send some test data to the user.
	'''
	global ssl_sock
	for i in range(0, count):
		ssl_sock.write('{"userId":' + str(user) + ',"sessionId":' + str(session) + ',"payload":"' + str(payload) + '"}')
		print('{"userId":' + str(user) + ',"sessionId":' + str(session) + ',"payload":"' + str(payload) + '"}')
		time.sleep(sleep)

def help():
	''' Display the supported commands.
	'''
	print("Supported commands:")
	print("   help or ? - display available commands.")
	print("   quit - quite the test driver")
	print("   test - write a sample message to the socket 10 times (JSON wrapping is automatic)")

def handleInput(userInput):
	''' Determine the action to take based on user input.
	'''
	if (userInput == 'help' or userInput == '?'):
		help()
	elif (userInput == 'quit'):
		print("Terminating...")
		close()
	elif ('test' in userInput):
		test(1, 0, "TEST PAYLOAD", 10, 1) 

def prompt():
	''' Prompt the user to enter a command (if they want).
	'''
	print("-----------------------------------------")
	print("              Rabbit Driver              ") 
	print("Type 'help' or '?' for available commands")
	print("-----------------------------------------")

	# Handle the first user input.
	userInput = raw_input(">> ")
	handleInput(userInput)

	# Here's the actual prompt
	while (userInput != 'quit'):
		userInput = raw_input(">> ")
		handleInput(userInput)

def main():
	''' The main driver for this test module. Create the secure socket connection
	and the jump into the user input loop.
	'''
	try:
		prompt()
	except Exception as e:
		print("[ERROR] " + str(e))

# Let it rip
if __name__ == '__main__':
	main()
