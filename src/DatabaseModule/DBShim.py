'''
File: DBShim.py
Author: Christopher Wood, caw4567@rit.edu
'''

import sys
sys.path.append("../CryptoModule/")
from KeyManager import KeyManager
import sqlite3 as lite
import traceback
import hashlib, hmac

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

			# See if there are other connections to this database
			if (db in DBShim.connectionMap):
				DBShim.connectionMap[db] = DBShim.connectionMap[db] + 1
			else: 
				DBShim.connectionMap[db] = 1

	def closeConnection(self):
		''' Terminate the database connection.
		'''
		if (self.connAlive):
			self.conn.close()
			DBShim.connectionMap[self.dbString] = DBShim.connectionMap[self.dbString] - 1

	def maskData(self, data, table):
		''' Generate the mask for the database entries.
		'''
		#firstHalf = self.keyMgr.getMasterKey() + self.keyMgr.getPublicKey()
		#secondPayload = data + table
		#secondHalf = self.sha3.Keccak((len(bytes(secondPayload)), secondPayload.encode("hex")))
		return hmac.new(self.keyMgr.getMasterKey(), data + table, hashlib.sha512).hexdigest()

	def insertIntoTable(self, table, rowAttributes, rowContents):
		''' Insert a row into the specified table. Data filtering happens on behalf of the caller.
		'''
		# Build the entry value for the query
		emptyVal = "("
		for i in range(0, len(rowContents) - 1):
			emptyVal = emptyVal + "?,"
		emptyVal = emptyVal + "?)"

		# Masking the data:
		# 1. pass user ID as a salt and list of columns to be encrypted
		# 2. hash table name and concat to hash of user ID
		# 3. hash master key (which can be obtained from the logger) and appent previous string
		# 4. encrypt the specified columns (indicated by indices) using this new key

		# Execute the query...
		print('INSERT INTO ' + table + ' ' + rowAttributes + " VALUES " + str(rowContents))
		self.cursor.execute("INSERT INTO " + table + rowAttributes + " VALUES " + emptyVal, rowContents)
		self.conn.commit()

	def replaceInTable(self, table, rowAttributes, rowContents):
		''' Insert or replace the row contents into the specified table. This is probably not safe.
		'''
		emptyVal = "("
		for i in range(0, len(rowContents) - 1):
			emptyVal = emptyVal + "?,"
		emptyVal = emptyVal + "?)"

		# Execute the query...
		print('INSERT OR REPLACE INTO ' + table + rowAttributes + ' VALUES ' + emptyVal)
		self.cursor.execute('INSERT OR REPLACE INTO ' + table + rowAttributes + ' VALUES ' + emptyVal, rowContents)
		self.conn.commit()

	def executeMultiQuery(self, table, valueMap):
		''' Query for a set of database elements that match all key/value pairs
		in the valueMap.
		'''
		queryString = "SELECT * from " + table + " WHERE "
		keys = valueMap.keys()
		for i in range(0, len(keys) - 1):
			queryString = queryString + keys[i] + " = '" + str(valueMap[keys[i]]) + "' and "
		queryString = queryString + keys[len(keys) - 1] + " = '" + str(valueMap[keys[len(keys) - 1]]) + "'"
		print("executing multiple query: " + str(queryString))
		self.cursor.execute(queryString)
		return self.cursor.fetchall()

	def executeRawQuery(self, query):
		''' Execute a user-defined query on the specified table. 

		**** WARNING: THIS IS NOT SAFE. FOR DEVELOPMENT PURPOSES ONLY. ****
		'''
		self.cursor.execute(query)
		return self.cursor.fetchall()

	def executeQuery(self, table, key, value):
		''' Perform a query on the specified table.
		'''
		print("SELECT * FROM " + table + " WHERE " + key + " = '%s'" % value)
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
	shim = DBShim("users.db")
	rows = shim.executeQuery("users", "userId", "1")
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