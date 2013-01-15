'''
File: TrafficProxyDriver.py
Author: Christopher A. Wood, caw4567@rit.edu
Usage:

	python TrafficProxyDriver.py host port

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
PORT = 9998
EventCount = 20

# The socket used in communication
ssl_sock = None

def close():
	''' Close the open socket.
	'''
	global ssl_sock
	ssl_sock.close()
	sys.exit(0)

def test(user, session, payload, count, sleep = 0):
	''' Send some test data to the user.
	'''
	global ssl_sock
	for i in range(0, count):
		ssl_sock.write('{"userId":' + str(user) + ',"sessionId":' + str(session) + ',"payload":"' + str(payload) + '"}')
		print('{"userId":' + str(user) + ',"sessionId":' + str(session) + ',"payload":"' + str(payload) + '"}')
		time.sleep(sleep)

def stressTest_1():
	''' Run a stress test on the system. 
	'''
	global EventCount
	global ssl_sock

	payload = "THIS IS A HUGE SIZED PAYLOAD THAT MOST APPLICATIONS WILL PROBABLY GENERATE" * 100
	user = 0
	session = 0

	for i in range(0, EventCount):
		print("Sending message: " + str(i))
		ssl_sock.write('{"userId":' + str(user) + ',"sessionId":' + str(session) + ',"payload":"' + str(payload) + '"}')

def stressTest_2():
	''' Run a stress test on the system. 
	'''
	global EventCount
	global ssl_sock

	payload = "THIS IS A NORMAL SIZED PAYLOAD THAT MOST APPLICATIONS WILL PROBABLY GENERATE"
	user = 0
	session = 0

	for i in range(0, EventCount):
		print("Sending message: " + str(i))
		ssl_sock.write('{"userId":' + str(user) + ',"sessionId":' + str(session) + ',"payload":"' + str(payload) + '"}')

def stressTest_3():
	''' Run a stress test on the system. 
	'''
	global EventCount
	global ssl_sock

	payload = "SMALL"
	user = 0
	session = 0

	for i in range(0, EventCount * 100): # bombard the logging system with messages
		print("Sending message: " + str(i))
		ssl_sock.write('{"userId":' + str(user) + ',"sessionId":' + str(session) + ',"payload":"' + str(payload) + '"}')

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
		test(0, 0, "TEST PAYLOAD", 10, 1) 
	elif ('stress' in userInput):
		stressTest_1()
		stressTest_2()
		stressTest_3()

def prompt():
	''' Prompt the user to enter a command (if they want).
	'''
	print("-----------------------------------------")
	print("            Traffic Proxy Driver         ")
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
	global ssl_sock
	try:
		if (len(sys.argv) == 3):
			# Create the socket using the specified host and port
			host = sys.argv[1]
			port = int(sys.argv[2])
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

			# Create the SSL context and then connect
			# This key/certificate should be signed by a trusted CA
			ssl_sock = ssl.wrap_socket(s, keyfile="../keys/key", certfile="../keys/cert", ca_certs="../keys/cert", cert_reqs=ssl.CERT_REQUIRED)
			ssl_sock.connect((host, port))

			# Display the server certificate information
			print repr(ssl_sock.getpeername())
			print ssl_sock.cipher()
			print pprint.pformat(ssl_sock.getpeercert())
			prompt()
		else:
			print("usage: python TrafficProxyDriver.py host port")
	except Exception as e:
		print("[ERROR] " + str(e))

# Let it rip
if __name__ == '__main__':
	main()
