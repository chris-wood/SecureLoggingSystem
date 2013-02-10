'''
File: DBShim.py
Author: Christopher Wood, caw4567@rit.edu
'''

import sys
sys.path.append("../CryptoModule/")
from KeyManager import KeyManager
import sqlite3 as lite
import logging
import traceback
import hashlib
from Crypto.Cipher import AES
from Crypto import Random

class DBShim(object):
	''' The shim for the database that is used to store arbitrary user/log/crypto related information.
	Other modules use this object to encapsulate access to their respective database.

	Ideally, there is low coupling between this class and the SQLite database, so that it's
	easy to migrate to another DB if needed.
	'''

	# Keep track of the number of connections open to each database (for debug/maintenance)
	connectionMap = {}

	def __init__(self, db, keyMgr):
		''' Initialize the shim to connect to a database.
		'''
		if (db != None and len(db) > 0):
			self.conn = lite.connect(db)
			self.conn.row_factory = lite.Row
			self.conn.text_factory = str
			self.cursor = self.conn.cursor()
			self.connAlive = True
			self.dbString = db
			self.keyMgr = keyMgr
			self.aesMode = AES.MODE_CBC

			# See if there are other connections to this database
			if (db in DBShim.connectionMap):
				DBShim.connectionMap[db] = DBShim.connectionMap[db] + 1
			else: 
				DBShim.connectionMap[db] = 1

			# Setup the logger
			logFile = 'abls.log'
			logging.basicConfig(filename=logFile,level=logging.DEBUG)

	def closeConnection(self):
		''' Terminate the database connection.
		'''
		if (self.connAlive):
			self.conn.close()
			DBShim.connectionMap[self.dbString] = DBShim.connectionMap[self.dbString] - 1

	def maskData(self, data, table):
		''' Generate the mask for the database entries. This should be invoked on every data 
		element that is marked as sensitive.
		'''
		#firstHalf = self.keyMgr.getMasterKey() + self.keyMgr.getPublicKey()
		#secondPayload = data + table
		#secondHalf = self.sha3.Keccak((len(bytes(secondPayload)), secondPayload.encode("hex")))

		#iv = Random.new().read(AES.block_size) # we need an IV of 16-bytes, this is also random...
		#key = Random.new().read(32)
		#ciphertext = AES.new(key, self.aesMode, iv).encrypt(key)
		key = hashlib.sha256(self.keyMgr.getMasterKey() + str(table)).digest()
		cipher = AES.new(key, AES.MODE_ECB)	

		# Make sure we're an even multiple of length 16
		plaintext = str(data)
		if (len(str(plaintext)) % 16 != 0):
			plaintext = plaintext + (' ' * (16 - len(plaintext) % 16))

		ciphertext = cipher.encrypt(plaintext)
		return ciphertext.encode("hex")

		#hf = hashlib.sha512()
		#hf.update(self.keyMgr.getMasterKey() + str(data) + str(table))
		#return hf.hexdigest()

	def insertIntoTable(self, table, rowAttributes, rowContents, rowMasks):
		''' Insert a row into the specified table. Data filtering happens on behalf of the caller.
		'''
		# Build the entry value for the query
		emptyVal = "("
		for i in range(0, len(rowContents) - 1):
			emptyVal = emptyVal + "?,"
		emptyVal = emptyVal + "?)"

		# Mask the data based on what's in rowMasks
		newRowContents = []
		for i in range(0, len(rowContents)):
			if (rowMasks[i]):
				newRowContents.append(self.maskData(rowContents[i], table))
			else:
				newRowContents.append(rowContents[i])

		# Execute the query
		logging.debug('INSERT INTO ' + table + ' ' + rowAttributes + " VALUES " + str(newRowContents))
		self.cursor.execute("INSERT INTO " + table + rowAttributes + " VALUES " + emptyVal, newRowContents)
		self.conn.commit()

	def replaceInTable(self, table, rowAttributes, rowContents, rowMasks):
		''' Insert or replace the row contents into the specified table. This is probably not safe.
		'''
		emptyVal = "("
		for i in range(0, len(rowContents) - 1):
			emptyVal = emptyVal + "?,"
		emptyVal = emptyVal + "?)"

		# Mask the data based on what's in rowMasks
		newRowContents = []
		for i in range(0, len(rowContents)):
			if (rowMasks[i]):
				newRowContents.append(self.maskData(rowContents[i], table))
			else:
				newRowContents.append(rowContents[i])

		# Execute the query...
		logging.debug('INSERT OR REPLACE INTO ' + table + rowAttributes + ' VALUES ' + str(newRowContents))
		self.cursor.execute('INSERT OR REPLACE INTO ' + table + rowAttributes + ' VALUES ' + emptyVal, newRowContents)
		self.conn.commit()

	def executeMultiQuery(self, table, valueMap, rowMasks):
		''' Query for a set of database elements that match all key/value pairs
		in the valueMap.
		'''

		# Build the query
		queryString = "SELECT * from " + table + " WHERE "
		keys = valueMap.keys()
		for i in range(0, len(keys) - 1):
			if (keys[i] in rowMasks):
				queryString = queryString + keys[i] + " = '" + self.maskData(valueMap[keys[i]], table) + "' and "
			else:
				queryString = queryString + keys[i] + " = '" + str(valueMap[keys[i]]) + "' and "
		if (keys[len(keys) - 1] in rowMasks):
			queryString = queryString + keys[len(keys) - 1] + " = '" + self.maskData(valueMap[keys[len(keys) - 1]], table) + "'"
		else:
			queryString = queryString + keys[len(keys) - 1] + " = '" + str(valueMap[keys[len(keys) - 1]]) + "'"

		logging.debug("executing multiple query: " + str(queryString))

		# Execute it
		self.cursor.execute(queryString)
		return self.cursor.fetchall()

	def executeRawQuery(self, query):
		''' Execute a user-defined query on the specified table. 

		**** WARNING: THIS IS NOT SAFE. FOR DEVELOPMENT PURPOSES ONLY. ****
		'''
		self.cursor.execute(query)
		return self.cursor.fetchall()

	def executeQuery(self, table, key, value, mask):
		''' Perform a query on the specified table.
		'''
		#print("SELECT * FROM " + table + " WHERE " + key + " = '%s'" % value)
		if (mask):
			logging.debug("SELECT * FROM " + table + " WHERE " + key + " = '%s'" % self.maskData(value, table))
			self.cursor.execute("SELECT * FROM " + table + " WHERE " + key + " = '%s'" % self.maskData(value, table))
		else:
			self.cursor.execute("SELECT * FROM " + table + " WHERE " + key + " = '%s'" % value)
		return self.cursor.fetchall()

	def randomQuery(self, table):
		''' Select a random row from the specified table (used by the crawlers).
		'''
		self.cursor.execute("SELECT * FROM " + table + " ORDER BY RANDOM () LIMIT 1")
		return self.cursor.fetchall()

def main():
	''' Unit test for this small module - verified by output inspection.
	'''
	print("Starting DB shim test...")
	shim = DBShim("users.db", KeyManager())
	rows = shim.executeQuery("users", "userId", "1", True)
	print(rows[0]["userId"])
	print(rows[0]["name"])
	print(rows[0]["email"])
	print(rows[0]["attributes"])

	# Mess around with the random queries
	print(shim.randomQuery("users"))

	print("Starting log shim test...")
	shim = DBShim("log.db")
	shim.insertIntoTable("log", "(userId, sessionId, epochId, message, xhash, yhash)", (1, 2, 0, "HELLO WORLD", 1337, 1337))
	shim.insertIntoTable("log", "(userId, sessionId, epochId, message, xhash, yhash)", (1, 2, 0, "HELLO WORLD", 123, 4444))
	shim.insertIntoTable("log", "(userId, sessionId, epochId, message, xhash, yhash)", (1, 2, 0, "HELLO WORLD", 123, 1312337))
	shim.insertIntoTable("log", "(userId, sessionId, epochId, message, xhash, yhash)", (1, 5, 0, "THIS WILL OR WILL NOT WORK", 123, 1312337))
	print(shim.executeQuery("log", "userId", 1))

	valueMap = {"userId" : 1, "sessionId" : 2}
	print(shim.executeMultiQuery("log", valueMap))
	valueMap = {"userId" : 1, "sessionId" : 10000}
	print(len(shim.executeMultiQuery("log", valueMap)))
	shim.replaceInTable("log", "(userId, sessionId, epochId, message, xhash, yhash)", (1, 5, 0, "CHANGED!", 123, 28928282828))
	print(shim.executeQuery("log", "userId", 1))	

	print("The last test.")
	print(shim.executeQuery("log", "userId", 1))

# Let it rip...
if (__name__ == '__main__'):
	main()

