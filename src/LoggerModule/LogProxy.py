'''
File: LogProxy.py
Author: Christopher A. Wood, caw4567@rit.edu
'''

import threading
import logging # Python logging module
from ClientObject import ClientObject
from ClientHandler import ClientHandler
import socket
import ssl
from OpenSSL import SSL
import Queue # thread-safe queue for producer/consumer implementations
from time import clock, time # for time-based extraction
from pykka.actor import ThreadingActor

class LogProxy(threading.Thread):
	''' This is an active object that accepts new data over its TCP socket 
	(meaning that it is kept separate from the main application that uses it)
	'''

	# The list of active sessions (IDs) that have been authenticated
	activeSessions = []

	def __init__(self, keyMgr):	
		''' Initialize the log proxy that intercepts traffic from the incoming source,
			makes sure it's authenticated, and then sets up a handler to parse all traffic.
		'''
		threading.Thread.__init__(self)
		self.running = False

		# Initialize the connection vars/fields
		self.HOST = 'localhost'
		self.PORT = 9998
		self.BUFFSIZE = 1024
		self.clientList = []
		self.handler = None
		self.serverSock = None

		# Persist the key manager reference
		self.keyMgr = keyMgr

		# Setup the Python logger
		self.lgr = logging.getLogger('abls')
		self.lgr.setLevel(logging.DEBUG)
		fh = logging.FileHandler('abls.log')
		fh.setLevel(logging.WARNING)
		frmt = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
		fh.setFormatter(frmt)
		self.lgr.addHandler(fh)

		# Set up the socket configuration parameters
		self.context = SSL.Context(SSL.SSLv23_METHOD)
		self.context.use_privatekey_file('./Keys/key') # our private key
		self.context.use_certificate_file('./Keys/cert') # our self-signed certificate

	def run(self):
		''' Run the log proxy and listen for incoming connections.
		'''
		address = (self.HOST, self.PORT)
		self.running = True
		self.serverSock = socket.socket()
		self.serverSock = SSL.Connection(self.context, self.serverSock)
		self.serverSock.bind(address)
		self.serverSock.listen(5)

		# Wait for incoming connections from clients
		while self.running:
			# Accept a new client connection 
			newsocket, fromaddr = self.serverSock.accept()
			
			# Wrap the socket up in a SSL connection for authentication and encryption
			'''connstream = ssl.wrap_socket(newsocket,
                                 server_side=True,
                                 certfile="./Keys/cert",
                                 keyfile="./Keys/key",
                                 ssl_version=ssl.PROTOCOL_TLSv1, # TODO: this should be a configurable parameter for ABLS
                                 cert_reqs=ssl.CERT_REQUIRED) # we require a certificate from the client for authentication
			'''
			#print("Client connected from {}.".format(fromaddr))
			self.lgr.debug("Client connected from {}.".format(fromaddr))

			# Start the handler thread
			handler = ClientHandler(self, self.keyMgr)
			handler.start()
			handler.clientList.append(ClientObject(newsocket, fromaddr, None)) # None should be connstream
			self.activeSessions.append(handler)

		self.serverSock.close()
		self.lgr.debug("- end -")
		#print("- end -")

	def get(self):
		''' Retrieve teh next element from the LogEntry queue.
		'''
		return self.queue.get()

	def kill(self):
		''' Terminate the thread.
		'''
		print("Killing the traffic proxy.")
		self.lgr.deubg("Killing the traffic proxy.")
		self.serverSock.close()
