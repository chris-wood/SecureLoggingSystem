'''
File: EventQueue.py
Author: Christopher Wood, caw4567@rit.edu
'''

import threading
import ClientObject
import ClientHandler
import socket
import Queue # thread-safe queue for producer/consumer implementations
from time import clock, time # for time-based extraction

class EventQueue(threading.Thread):
	'''
	This is an active queue that accepts new data over its TCP socket 
	(meaning that it is kept separate from the main application that uses it)
	'''

	# Socket configuration parameters
	# Ideally, these are pulled from a database somewhere
	HOST = 'localhost'
	PORT = 9998
	BUFFSIZE = 1024
	running  = False

	# The socket object
	serverSock = None

	# Client thread handlers (in case the keylogger needs to restart)
	clientList = []
	handler = None

	# The data bucket
	queue = Queue.Queue()

	def __init__(self):
		threading.Thread.__init__(self)
		self.running = False
		print("EventQueue created.")

	def run(self):
		address = (self.HOST, self.PORT)
		self.running = True
		self.serverSock = socket.socket()
		self.serverSock.bind(address)
		self.serverSock.listen(2)

		# Create the handler thread
		self.handler = ClientHandler.ClientHandler(self, self.queue)
		self.handler.start()

		# Wait for incoming connections
		while self.running:
			clientInfo = self.serverSock.accept()
			print("Client connected from {}.".format(clientInfo[1]))
			self.handler.clientList.append(ClientObject.ClientObject(clientInfo))

		self.serverSock.close()
		print("- end -")

	def get(self):
		'''
		Retrieve the next element from the LogEntry queue
		'''
		return self.queue.get()

	def kill(self):
		print("Killing the event queue thread.")
		self.serverSock.close()

