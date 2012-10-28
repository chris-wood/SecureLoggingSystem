'''
File: TrafficProxy.py
Author: Christopher A. Wood, caw4567@rit.edu
'''

import threading
import ClientObject
import ClientHandler
import socket
import ssl
from OpenSSL import SSL
import Queue # thread-safe queue for producer/consumer implementations
from time import clock, time # for time-based extraction
from pykka.actor import ThreadingActor

class TrafficProxy(threading.Thread):
	'''
	This is an active queue that accepts new data over its TCP socket 
	(meaning that it is kept separate from the main application that uses it)
	'''

	# The list of active sessions (IDs) that have been authenticated
	activeSessions = []

	def __init__(self):	
		# Initialize the traffic proxy that intercepts traffic from the incoming source,
		# makes sure it's authenticated, and then sets up a handler to parse all traffic
		threading.Thread.__init__(self)
		self.running = False

		# Initialize the connection vars/fields
		self.HOST = 'localhost'
		self.PORT = 9998
		self.BUFFSIZE = 1024
		self.clientList = []
		self.handler = None
		self.serverSock = None

		# Set up the socket configuration parameters
		self.context = SSL.Context(SSL.SSLv23_METHOD)
		self.context.use_privatekey_file('./keys/key')
		self.context.use_certificate_file('./keys/cert')

	def run(self):
		address = (self.HOST, self.PORT)
		self.running = True
		self.serverSock = socket.socket()
		self.serverSock = SSL.Connection(self.context, self.serverSock)
		self.serverSock.bind(address)
		self.serverSock.listen(5)

		# Wait for incoming connections from clients
		while self.running:
			# Accept a new client connection
			clientInfo = self.serverSock.accept()
			print("Client connected from {}.".format(clientInfo[1]))

			# Start the handler thread
			handler = ClientHandler.ClientHandler(self)
			handler.start()
			handler.clientList.append(ClientObject.ClientObject(clientInfo))
			self.activeSessions.append(handler)

		self.serverSock.close()
		print("- end -")

	def get(self):
		#Retrieve the next element from the LogEntry queue
		return self.queue.get()

	def kill(self):
		print("Killing the event queue thread.")
		self.serverSock.close()
