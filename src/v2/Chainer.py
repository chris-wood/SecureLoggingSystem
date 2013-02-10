'''
File: Chainer.py
Author: Christopher Wood, caw4567@rit.edu
'''

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
from timeit import Timer

# Action IDs
ACTION_ADD = 1
ACTION_DELETE = 2
ACTION_MODIFY = 3

# Object IDs
OBJECT_X = 1
OBJECT_Y = 2
OBJECT_Z = 3

# Maps for crypto data structures
initialLogEntityKey = {}
initialEventEntityKey = {}
logEntityKey = {}
eventEntityKey = {}
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
	logEntityKey = Random.new().read(32)
	eventEntityKey = Random.new().read(32)

	# These keys should be encrypted using CPABE for the (verifier role and user role)
	# so they can easily be recovered for verification
	msg = '{"userId":' + str(userId) + ',"sessionId":' + str(sessionId) + ',"action":' + str(0) + '}' 
	#print("verify msg: " + str(msg))
	policy = manager.ask({'command' : 'verifyPolicy', 'payload' : msg})
	encryptedLogEntityKey = encryptionModule.encrypt(logEntityKey, policy)
	encryptedEventEntityKey = encryptionModule.encrypt(eventEntityKey, policy)

	# Persist the encrypted keys
	keyShim.replaceInTable("InitialLogEntityKey", "(userId, sessionId, key, inserted_at)", (userId, sessionId, encryptedLogEntityKey, datetime.now().ctime()), [False, False, False, False]) 
	keyShim.replaceInTable("InitialEventEntityKey", "(userId, sessionId, key, inserted_at)", (userId, sessionId, encryptedEventEntityKey, datetime.now().ctime()), [False, False, False, False]) 
	#print("setting initial log and event entity key...")
	initialLogEntityKey[(userId, sessionId)] = logEntityKey
	initialEventEntityKey[(userId, sessionId)] = eventEntityKey
	#print(initialLogEntityKey[(userId, sessionId)])
	#print(initialEventEntityKey[(userId, sessionId)])

def addNewEvent(userId, sessionId, message, logInfo):
	''' Construct a new event to add to the log. It is assumed the epoch key is 
	already initialized before this happens.
	'''
	# Some definitions
	xi = None
	yi = None
	zi = None
	payload = ""

	# Generate the initial log results
	valueMap = {"userId" : userId, "sessionId" : sessionId}
	logResults = logShim.executeMultiQuery("Log", valueMap, ["userId", "sessionId"])

	# Check to see if we are starting a new chain or appending to an existing one.
	if (len(logResults) == 0):
		logEntityKey[(userId, sessionId)] = initialLogEntityKey[(userId, sessionId)]
		eventEntityKey[(userId, sessionId)] = initialEventEntityKey[(userId, sessionId)]
		keyShim.insertIntoTable("LogEntityKey", "(userId, sessionId, key, inserted_at)", (userId, sessionId, logEntityKey[(userId, sessionId)], datetime.now().ctime()), [True, True, False, False])
		keyShim.insertIntoTable("EventEntityKey", "(userId, sessionId, key, inserted_at)", (userId, sessionId, eventEntityKey[(userId, sessionId)], datetime.now().ctime()), [True, True, False, False])
		payload = str(userId) + str(sessionId) + str(0) + str(message) + str(0) # hash of this entry is (user, session, epoch, msg, previous == 0)
	else:
		# Update the epoch/entity key values from the database
		length = len(logResults)
		valueMap = {"userId" : userId, "sessionId" : sessionId}
		logEntityKeyResults = keyShim.executeMultiQuery("LogEntityKey", valueMap, ["userId", "sessionId"])
		logEntityKey[(userId, sessionId)] = logEntityKeyResults[len(logEntityKeyResults) - 1]["key"]

		eventEntityKeyResults = keyShim.executeMultiQuery("EventEntityKey", valueMap, ["userId", "sessionId"])
		eventEntityKey[(userId, sessionId)] = eventEntityKeyResults[len(eventEntityKeyResults) - 1]["key"]

		# Now, generate the payload for this log entry
		logLength = len(logResults)
		lastHash = logResults[length - 1]["digest"]
		payload = str(userId) + str(0) + str(logLength) + str(message) + str(lastHash)

	# Finally, query the data to build the final log entry
	valueMap = {"userId" : userId, "sessionId" : sessionId}
	logResults = logShim.executeMultiQuery("Log", valueMap, ["userId", "sessionId"])

	# Now hash the hash chain entry... But first, build up the data that's needed
	currKey = str(logEntityKey[(userId, sessionId)])

	# Here are the elements for the log entry tuple
	xi = sha3.Keccak((len(bytes(payload)), payload.encode("hex"))) # just a plain old hash
	yi = hmac.new(currKey, xi.encode("hex"), hashlib.sha512).hexdigest()

	# Store the latest entity digest
	lastEntityDigest = hmac.new(currKey, xi, hashlib.sha512).hexdigest()
	logShim.replaceInTable("LogChainEntity", "(userId, sessionId, digest, inserted_at)", (userId, sessionId, lastEntityDigest, datetime.now().ctime()), [False, False, False, False])
	logEntityKey[(userId, sessionId)] = hmac.new(currKey, "some constant value", hashlib.sha512).hexdigest() # update the keys
	keyShim.insertIntoTable("LogEntityKey", "(userId, sessionId, key, inserted_at)", (userId, sessionId, logEntityKey[(userId, sessionId)], datetime.now().ctime()), [False, False, False, False])

	# Store the log element now
	logShim.insertIntoTable("Log", "(userId, sessionId, payload, digest, link, inserted_at)", (userId, sessionId, message, xi, yi, datetime.now().ctime()), [False, False, False, False, False, False])

	# Store the appropriate event information now (handle all three cases as needed)
	salt = Random.new().read(32) # some random salt... always stored, just in case
	#print("Salt: " + str(salt))
	if (logInfo.object == None and logInfo.affectedUsers == None): # Only event with null object and affectedUsers
		logShim.insertIntoTable("Event", "(userId, sessionId, action, salt)", (userId, sessionId, logInfo.action, salt), [False, False, False, False])
	elif (logInfo.object == None): # Only event with object 
		logShim.insertIntoTable("Event", "(userId, sessionId, action, salt)", (userId, sessionId, logInfo.action, salt), [False, False, False, False])
		valueMap = {"userId" : userId, "sessionId" : sessionId}
		eventResults = logShim.executeMultiQuery("Event", valueMap, [])
		lastEvent = eventResults[len(eventResults) - 1]

		# Insert info info the affected user table
		eventId = lastEvent["eventId"]
		for uid in logInfo.affectedUsers:
			logShim.insertIntoTable("AffectedUserGroup", "(eventId, userId)", (eventId, uid), [False, True])
	elif (logInfo.affectedUsers == None): #
		logShim.insertIntoTable("Event", "(userId, sessionId, action, object, salt)", (userId, sessionId, logInfo.action, logInfo.object, salt), [False, False, False, False, False])
	else:
		logShim.insertIntoTable("Event", "(userId, sessionId, action, object, salt)", (userId, sessionId, logInfo.action, logInfo.object, salt), [False, False, False, False, False])
		valueMap = {"userId" : userId, "sessionId" : sessionId}
		eventResults = logShim.executeMultiQuery("Event", valueMap, [])
		lastEvent = eventResults[len(eventResults) - 1]

		# Insert info info the affected user table
		eventId = lastEvent["eventId"]
		for uid in logInfo.affectedUsers:
			logShim.insertIntoTable("AffectedUserGroup", "(eventId, userId)", (eventId, uid), [False, True])

	# Debug
	#print("Inserted the log: " + str((userId, sessionId, message, xi, yi)))

def processLogEntry(msg):
	''' This method is responsible for processing a single msg retrieved from the log proxy.
	'''
	# Parse the host application data
	entry = LogEntry(jsonString = msg)

	#print("requesting policy")
	policy = manager.ask({'command' : 'policy', 'payload' : msg})
	key = None
	iv = None
	#print("Policy for the piece of data: " + str(policy))
	if not ((entry.userId, entry.sessionId, policy) in policyKeyMap.keys()) or True: # the or True was added to subvert the policy check for experiment purposes
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
	results = []
	try:
		results = keyShim.executeMultiQuery("InitialLogEntityKey", valueMap, ["userId", "sessionId"])
	except:
		print("Error: Unable to update the initialEpochKey table")
	if (len(results) == 0):
		createSession(int(entry.userId), int(entry.sessionId))

	# Now store the event in the log 
	addNewEvent(userId = int(entry.userId), sessionId = int(entry.sessionId), message = ciphertext.encode("hex"), logInfo = entry)

def help():
	''' Display the available commands to the user.
	'''
	print("Type 'good' or 'bad' to insert good or bad messages into the log.")

def insertGoodLog():
	''' Insert a good entry into the log (i.e. it doesn't violate the audit rule).
	'''
	logEntry = '{"userId": 1, "sessionId": 1, "action": ' + str(ACTION_MODIFY) + '}'
	processLogEntry(logEntry)

def insertBadLog():
	''' Insert a bad entry into the log (i.e. it violates an audit rule).
	'''
	logEntry = '{"userId": 3, "sessionId": 1, "action": ' + str(ACTION_MODIFY) + ', "object": ' + str(OBJECT_X) + '}' # bad action
	processLogEntry(logEntry)

def handleInput(userInput):
	''' Helper function to handle user input.
	'''
	if (userInput == 'help' or userInput == '?'):
		help()
	elif ('good' in userInput):
		insertGoodLog()
	elif ('bad' in userInput):
		insertBadLog()

def main():
	# Some sample log messages that adhere to the log format
	log1 = '{"userId": 1, "sessionId": 1, "action": ' + str(ACTION_MODIFY) + '}'
	log3 = '{"userId": 1, "sessionId": 1, "action": ' + str(ACTION_MODIFY) + ', "affectedUsers" : [1,2,3]}'
	log4 = '{"userId": 1, "sessionId": 1, "action": ' + str(ACTION_MODIFY) + ', "object": ' + str(OBJECT_X) + ', "affectedUsers" : [1,2,3]}'
	print (json.loads(log1))
	print (json.loads(log3))
	print (json.loads(log4))

	for i in range(0, 100):
		processLogEntry(log4)

	# Shove the test logs into the log parsing method...
	with open("times_diff_events.csv", 'w') as f:
		for i in range(1, 100):
			start = time.time()
			for j in range(0, i):
				#log = '{"userId": ' + str(j) + ', "sessionId": 1, "action": ' + str(ACTION_MODIFY) + '}'
				processLogEntry(log1)
			end = time.time()
			f.write(str(i) + "," + str((end - start) * 1000) + "\n")

	# Jump into the input-handling loop...
	print("---------------------------")
	print("Type 'help' or '?' for help")
	print("---------------------------")
	userInput = raw_input(">> ")
	handleInput(userInput)
	while (userInput != 'quit'):
		userInput = raw_input(">> ")
		handleInput(userInput)

if (__name__ == "__main__"):
	main()
