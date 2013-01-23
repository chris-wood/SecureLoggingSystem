'''
File: AuditProxy.py
Author: Christopher A. Wood, caw4567@rit.edu
'''

import threading
import logging # Python logging module
from AuditClientObject import AuditClientObject
from AuditClientHandler import AuditClientHandler
import socket
import Queue # thread-safe queue for producer/consumer implementations
from time import clock, time # for time-based extraction
from pykka.actor import ThreadingActor

class AuditProxy(threading.Thread):
	''' This is an active object that accepts new data over its TCP socket 
	(meaning that it is kept separate from the main application that uses it)
	'''

	# The list of active sessions (IDs) that have been authenticated
	activeSessions = []

	def __init__(self, params, keyMgr):	
		''' Initialize the traffic proxy that intercepts traffic from the incoming source,
			makes sure it's authenticated, and then sets up a handler to parse all traffic.
		'''
		threading.Thread.__init__(self)
		self.running = False

		# Persist the key manager and params
		self.keyMgr = keyMgr
		self.params = params

		# Initialize the connection vars/fields
		self.HOST = 'localhost'
		self.PORT = 9999 # TODO: pull this out into a configuration file
		self.BUFFSIZE = 1024
		self.clientList = []
		self.handler = None
		self.serverSock = None

	def run(self):
		''' Run the traffic proxy and listen for incoming connections.
		'''
		address = (self.HOST, self.PORT)
		self.running = True
		self.serverSock = socket.socket()
		self.serverSock.bind(address)
		self.serverSock.listen(5)

		# Wait for incoming connections from clients
		while self.running:
			# Accept a new client connection 
			newsocket, fromaddr = self.serverSock.accept()

			# Start the handler thread
			handler = AuditClientHandler(self,self.params,self.keyMgr)
			handler.start()
			handler.clientList.append(AuditClientObject(newsocket, fromaddr, None)) # None should be connstream
			self.activeSessions.append(handler)

		self.serverSock.close()

	def get(self):
		''' Retrieve the next element from the LogEntry queue.
		'''
		return self.queue.get()

	def kill(self):
		''' Terminate the thread.
		'''
		self.serverSock.close()
