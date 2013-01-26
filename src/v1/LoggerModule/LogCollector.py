'''
File: LogCollector.py
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

class LogCollector(threading.Thread):
	''' The singleton log collector instance that collates database entries from other active 
	threads in the system to be persisted to the appropriate database.
	'''

	# The list of active sessions (IDs) that have been authenticated
	activeSessions = []

	def __init__(self, params, keyMgr):	
		''' Initialize the log proxy that intercepts traffic from the incoming source,
			makes sure it's authenticated, and then sets up a handler to parse all traffic.
		'''
		threading.Thread.__init__(self)
		self.running = False

		# Persist the key manager reference and parameters 
		self.keyMgr = keyMgr
		self.params = params
		self.queue = []

		# Command IDs for the collector
		self.INSERT = 1
		self.REPLACE = 2
		self.MULTI_QUERY = 3

	def run(self):
		''' Run the log collector to collate log messages from the other log instances
		'''
		# Create the appropriate database shims
		self.logShim = DBShim.DBShim(self.params["LOG_DB"], self.keyMgr)
		self.keyShim = DBShim.DBShim(self.params["KEY_DB"], self.keyMgr)
		self.userShim = DBShim.DBShim(self.params["USER_DB"], self.keyMgr)

		# Map the tables to DB shims (based on the DB schema)
		self.tableMap = {}
		self.tableMap["log"] = self.logShim
		self.tableMap["entityKey"] = self.keyShim
		self.tableMap["epochKey"] = self.keyShim
		self.tableMap["entity"] = self.logShim
		self.tableMap["epoch"] = self.logShim
		self.tableMap["initialEpochKey"] = self.keyShim
		self.tableMap["initialEntityKey"] = self.keyShim

		# Just loop over the queue and wait to handle all incoming database events
		while not self.stopped():
			msg = self.queue.get()
			self.handleDatabaseEntry(msg)

	def handleDatabaseEntry(self, msg):
		''' Handle the message tuple 
		    (command, table, [:params])
		'''
		command = msg(0)
		table = msg(1)
		if (command == self.INSERT):
			cols = msg(2)
			data = msg(3)
			mask = msg(4)
			self.tableMap[table].insertIntoTable(table, cols, data, mask)
		elif (command == SELF.REPLACE):
			cols = msg(2)
			data = msg(3)
			mask = msg(4)
			self.tableMap[table].replaceInTable(table, cols, data, mask)
		elif (command == SELF.MULTI_QUERY):
			values = msg(2)
			mask = msg(3)
			self.tableMap[table].executeMultiQuery(table, values, mask)
		else:
			raise Exception("Invalid log collector command.")

	def stop(self):
		''' Stop this logging thread.
		'''
		self._stop.set()

	def stopped(self):
		''' Check to see if this logging thread was stopped correctly.
		''' 
		return self._stop.isSet()
