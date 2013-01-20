'''
File: bootstrap.py
Author: Christopher Wood, caw4567@rit.edu
Usage:

	python bootstrap.py 

'''

import sys
import time
import threading
import traceback
from datetime import datetime
import uuid
import hashlib

sys.path.append("./DatabaseModule")
sys.path.append("./CryptoModule")
from KeyManager import KeyManager
from DBShim import DBShim

def bootstrap():
	''' Bootstrap the database from the database with some dummy data.
	'''
	keyMgr = KeyManager()
	# Wipe the data if we're in debug mode
	print("Debug: Clearing the log database")

	# Check to see if we need to clear the table
	# This is specific to SQLite - coupling needs to be removed
	shim = DBShim("/Users/caw/Projects/SecureLoggingSystem/src/DatabaseModule/log.db", keyMgr)
	tableResults = shim.executeRawQuery("SELECT name FROM sqlite_master WHERE type='table' AND name='log'")
	if (len(tableResults) != 0):
		shim.executeRawQuery("DELETE FROM log")
	tableResults = shim.executeRawQuery("SELECT name FROM sqlite_master WHERE type='table' AND name='entity'")
	if (len(tableResults) != 0):
		shim.executeRawQuery("DELETE FROM entity")
	tableResults = shim.executeRawQuery("SELECT name FROM sqlite_master WHERE type='table' AND name='epoch'")
	if (len(tableResults) != 0):
		shim.executeRawQuery("DELETE FROM epoch")


	# Check to see if we need to clear the table
	# This is specific to SQLite - it needs to be less coupled to SQLite
	shim = DBShim("/Users/caw/Projects/SecureLoggingSystem/src/DatabaseModule/users.db", keyMgr)
	tableResults = shim.executeRawQuery("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
	if (len(tableResults) != 0):
		# Delete the contents in the table
		shim.executeRawQuery("DELETE FROM users")
		print("Initializing dummy data into the users table")
		
		# Create some dummy data for the database
		date = datetime.now()
		shim.insertIntoTable("users", "(userId, name, email, attributes, inserted_at, modified_at)", (0, "alice", "alice@test.com", "one", date, date), None)
		shim.insertIntoTable("users", "(userId, name, email, attributes, inserted_at, modified_at)", (1, "bob", "bob@test.com", "two", date, date), None)
		shim.insertIntoTable("users", "(userId, name, email, attributes, inserted_at, modified_at)", (2, "chris", "chris@test.com", "three", date, date), None)

	# Check to see if we need to clear the table
	# This is specific to SQLite - it needs to be less coupled to SQLite
	shim = DBShim("/Users/caw/Projects/SecureLoggingSystem/src/DatabaseModule/audit_users.db", keyMgr)
	tableResults = shim.executeRawQuery("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_users'")
	if (len(tableResults) != 0):
		# Delete the contents in the table
		shim.executeRawQuery("DELETE FROM audit_users")
		print("Initializing dummy data into the users table")
		
		# Create some dummy data for the database
		date = datetime.now()
		alicePassword = "alicePassword"
		bobPassword = "bobPassword"
		chrisPassword = "chrisPassword"

		# Generate the passwords/salts
		salt = str(uuid.uuid4())
		hashed_password = hashlib.sha512(alicePassword + salt).hexdigest()
		shim.insertIntoTable("audit_users", "(userId, userName, email, password, salt, inserted_at, modified_at)", (0, "alice", "alice@test.com", hashed_password, salt, date, date), None)
		salt = str(uuid.uuid4())
		hashed_password = hashlib.sha512(bobPassword + salt).hexdigest()
		shim.insertIntoTable("audit_users", "(userId, userName, email, password, salt, inserted_at, modified_at)", (1, "bob", "bob@test.com", hashed_password, salt, date, date), None)
		salt = str(uuid.uuid4())
		hashed_password = hashlib.sha512(chrisPassword + salt).hexdigest()
		shim.insertIntoTable("audit_users", "(userId, userName, email, password, salt, inserted_at, modified_at)", (2, "chris", "chris@test.com", hashed_password, salt, date, date), None)

if (__name__ == "__main__"):
	bootstrap()