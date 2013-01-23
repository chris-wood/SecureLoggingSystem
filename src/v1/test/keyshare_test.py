import sys
sys.path.append("../LoggerModule/")
from EncryptionModule import EncryptionModule
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.core.engine.util import objectToBytes,bytesToObject

## Test random function
#group = PairingGroup('SS512')
#print(group.random(G1))
#print(group.random(G1))
#print(group.random(G1))
#print(group.random(G1))
#print(group.random(G1))

# The test policy and plaintext
policy = '((one or three))' # needs to be in parentheses (because it's a gate!)
attrs = ['ONE', 'TWO', 'THREE']
msg = "Hello world!"

# The two separate encryption modules
enc1 = EncryptionModule()
enc2 = EncryptionModule()

 # Test before sharing
(mk1, pk1) = enc1.getValues()
(mk2, pk2) = enc2.getValues()
print("Master keys (before sharing)")
print(objectToBytes(mk1, PairingGroup('SS512')) == objectToBytes(mk2, PairingGroup('SS512'))) 
print("Public keys (before sharing)")
print(objectToBytes(pk1, PairingGroup('SS512')) == objectToBytes(pk2, PairingGroup('SS512')))

# Test before sharing the keys
ct1 = enc1.encrypt(msg, policy)
ct2 = enc2.encrypt(msg, policy)
sk1 = enc1.generateUserKey(attrs) # takes a list of attributes (in caps?)
sk2 = enc2.generateUserKey(attrs) # takes a list of attributes (in caps?)
#print(enc1.decrypt(sk1, ct2)[1])
print(enc1.decrypt(sk2, ct2)[1])

# Dipslay master keys
(mk1, pk1) = enc1.getValues()
(mk2, pk2) = enc2.getValues()
enc2.set(mk1, pk1)
(mk2, pk2) = enc2.getValues()
print("Master keys (after sharing)")
print(objectToBytes(mk1, PairingGroup('SS512')) == objectToBytes(mk2, PairingGroup('SS512'))) 
print("Public keys (after sharing)")
print(objectToBytes(pk1, PairingGroup('SS512')) == objectToBytes(pk2, PairingGroup('SS512')))

ct1 = enc1.encrypt(msg, policy)
ct2 = enc2.encrypt(msg, policy)
sk1 = enc1.generateUserKey(attrs) # takes a list of attributes (in caps?)
sk2 = enc2.generateUserKey(attrs) # takes a list of attributes (in caps?)
print(enc1.decrypt(sk1, ct2)[1])
print(enc1.decrypt(sk2, ct2)[1])

# RESULT: MASTER/PUBLIC KEY MUST BE SHARED IN ORDER TO GENERATE THE RIGHT USER KEYS FOR DECRYPTION 