# 1. define JSON test data
# 2. define stub for function that parses test data and extracts information for the log tables
# 3. write up some basic audit rules

from Keccak import Keccak 
from DBShim import DBShim
from KeyManager import KeyManager
from LogEntry import LogEntry
from PolicyManager import PolicyManager
from EncryptionModule import EncryptionModule
from Crypto.Cipher import AES
from Crypto import Random
import hashlib
import hmac
import json
import time
from datetime import datetime

# Action IDs
ACTION_LOGIN = 1
ACTION_LOGOUT = 2
ACTION_ADD = 3
ACTION_DELETE = 4
ACTION_MODIFY = 5

# Object IDs
OBJECT_X = 1
OBJECT_Y = 2
OBJECT_Z = 3

# Maps for crypto data structures
initialEntityKey = {}
entityKey = {}
policyKeyMap = {}

# Crypto entities
keyMgr = KeyManager()
encryptionModule = EncryptionModule(keyMgr)
sha3 = Keccak()
aesMode = AES.MODE_CBC

# The policy manager
params = {"USER_DB" : "/Users/caw/Projects/SecureLoggingSystem/src/v2/user.db", "LOG_DB" : "/Users/caw/Projects/SecureLoggingSystem/src/v2/log.db", "KEY_DB" : "/Users/caw/Projects/SecureLoggingSystem/src/v2/key.db"}
manager = PolicyManager.start(params, keyMgr)

# Create the shims...
logShim = DBShim(params["LOG_DB"], keyMgr)
keyShim = DBShim(params["KEY_DB"], keyMgr)

def createSession(userId, sessionId):
	''' Initialize the authentication keys that are used when verifying the 
	entries in the log database.
	'''

	# Generate the epoch and entity keys (both are random 32-bytes strings) - used for verification (integrity) only
	epochKey = Random.new().read(32)
	entityKey = Random.new().read(32)

	# These keys should be encrypted using CPABE for the (verifier role and user role)
	# so they can easily be recovered for verification
	msg = '{"userId":' + str(userId) + ',"sessionId":' + str(sessionId) + ',"action":' + str(0) + '}' 
	print("verify msg: " + str(msg))
	policy = manager.ask({'command' : 'verifyPolicy', 'payload' : msg})
	encryptedEntityKey = encryptionModule.encrypt(entityKey, policy)

	# Persist the encrypted keys
	keyShim.replaceInTable("initialEntityKey", "(userId, sessionId, key, inserted_at)", (userId, sessionId, encryptedEntityKey, datetime.now().ctime()), [True, True, False, False]) 
	print("setting initial entity key...")
	initialEntityKey[(userId, sessionId)] = entityKey
	print(initialEntityKey[(userId, sessionId)])

def addNewEvent(userId, sessionId, message):
	''' Construct a new event to add to the log. It is assumed the epoch key is 
	already initialized before this happens.
	'''
	# Some definitions
	xi = None
	yi = None
	zi = None
	payload = ""
	lastEpochDigest = None

	# Generate the initial log results
	valueMap = {"userId" : userId, "sessionId" : sessionId}
	logResults = logShim.executeMultiQuery("log", valueMap, ["userId", "sessionId"])

	# Check to see if we are starting a new chain or appending to an existing one.
	if (len(logResults) == 0):
		entityKey[(userId, sessionId)] = initialEntityKey[(userId, sessionId)]
		keyShim.insertIntoTable("entityKey", "(userId, sessionId, key, inserted_at)", (userId, sessionId, entityKey[(userId, sessionId)], datetime.now().ctime()), [True, True, False, False])
		payload = str(userId) + str(sessionId) + str(0) + str(message) + str(0) # hash of this entry is (user, session, epoch, msg, previous == 0)
	else:
		# Update the epoch/entity key values from the database
		length = len(logResults)
		valueMap = {"userId" : userId, "sessionId" : sessionId}
		entityKeyResults = keyShim.executeMultiQuery("entityKey", valueMap, ["userId", "sessionId"])
		entityKey[(userId, sessionId)] = entityKeyResults[len(entityKeyResults) - 1]["key"]

		# Now, generate the payload for this log entry
		logLength = len(logResults)
		lastHash = logResults[length - 1]["xhash"]
		payload = str(userId) + str(0) + str(logLength) + str(message) + str(lastHash)

	# Finally, query the data to build the final log entry
	valueMap = {"userId" : userId, "sessionId" : sessionId}
	logResults = logShim.executeMultiQuery("log", valueMap, ["userId", "sessionId"])

	# Now hash the hash chain entry... But first, build up the data that's needed
	currKey = str(entityKey[(userId, sessionId)])

	# Here are the elements for the log entry tuple
	xi = sha3.Keccak((len(bytes(payload)), payload.encode("hex"))) # just a plain old hash
	yi = hmac.new(currKey, xi.encode("hex"), hashlib.sha512).hexdigest()

	# Store the latest entity digest
	lastEntityDigest = hmac.new(currKey, xi, hashlib.sha512).hexdigest()
	logShim.replaceInTable("LogChainEntity", "(userId, sessionId, digest, inserted_at)", (userId, sessionId, lastEntityDigest, datetime.now().ctime()), [True, True, False, False])
	entityKey[(userId, sessionId)] = hmac.new(currKey, "some constant value", hashlib.sha512).hexdigest() # update the keys
	keyShim.insertIntoTable("entityKey", "(userId, sessionId, key, inserted_at)", (userId, sessionId, entityKey[(userId, sessionId)], datetime.now().ctime()), [True, True, False, False])

	# Store the elements now
	logShim.insertIntoTable("Log", "(userId, sessionId, payload, digest, link, inserted_at)", (userId, sessionId, message, xi, yi, datetime.now().ctime()), [True, True, False, False, False, False])

	# Debug
	print("Inserted the log: " + str((userId, sessionId, message, xi, yi)))

def processLogEntry(msg):
	''' This method is responsible for processing a single msg retrieved from the log proxy.
	'''
	# Parse the host application data
	entry = LogEntry(jsonString = msg)

	print("requesting policy")
	policy = manager.ask({'command' : 'policy', 'payload' : msg})
	key = None
	iv = None
	print("Policy for the piece of data: " + str(policy))
	if not ((entry.userId, entry.sessionId, policy) in policyKeyMap.keys()):
		iv = Random.new().read(AES.block_size) # we need an IV of 16-bytes, this is also random...
		key = Random.new().read(32)

		# Encrypt the key using the policy and store it in memory and in the database
		encryptedKey = encryptionModule.encrypt(key, policy)
		policyKeyMap[(entry.userId, entry.sessionId, policy)] = (key, iv)
		keyShim.insertIntoTable("policyKey", "(userId, sessionId, policy, key, iv, inserted_at)", (entry.userId, entry.sessionId, policy, encryptedKey, iv, datetime.now().ctime()), [True, True, False, False, False, False])
	else:
		key = policyKeyMap[(entry.userId, entry.sessionId, policy)][0]
		iv = policyKeyMap[(entry.userId, entry.sessionId, policy)][1]

	# Pad the data if necessary to make it a multiple of 16
	plaintext = msg
	if (len(str(plaintext)) % 16 != 0):
		plaintext = plaintext + (' ' * (16 - len(plaintext) % 16))
	ciphertext = AES.new(key, aesMode, iv).encrypt(plaintext)

	# See if this is a new session that we need to manage, or if it's part of an existing session
	valueMap = {"userId" : entry.userId, "sessionId" : entry.sessionId}
	try:
		results = keyShim.executeMultiQuery("initialEntityKey", valueMap, ["userId", "sessionId"])
	except:
		print("Error: Unable to update the initialEpochKey table")
	if (len(results) == 0):
		createSession(int(entry.userId), int(entry.sessionId))

	# Now store the event in the log 
	addNewEvent(int(entry.userId), int(entry.sessionId), ciphertext.encode("hex"))

def main():
	# Some sample log messages
	log1 = '{"userId": 1, "sessionId": 1, "action": ' + str(ACTION_LOGIN) + '}'
	log2 = '{"userId": 1, "sessionId": 1, "action": ' + str(ACTION_LOGIN) + ', "object": ' + str(OBJECT_X) + '}'
	log3 = '{"userId": 1, "sessionId": 1, "action": ' + str(ACTION_LOGIN) + ', "object": ' + str(OBJECT_X) + ', "affectedUsers" : [1,2,3]}'
	print (json.loads(log1))
	print (json.loads(log2))
	print (json.loads(log3))

	# Shove the test logs into the log parsing method...
	processLogEntry(log1)

if (__name__ == "__main__"):
	main()
