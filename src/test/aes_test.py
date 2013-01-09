from Crypto.Cipher import AES
from Crypto import Random
import hashlib, hmac
import time
import random

# Generate a random key
key = hmac.new("\EFx" * 20, str(time.time() * (1000000 * random.random())), hashlib.sha512).hexdigest()
mode = AES.MODE_CBC

iv = Random.new().read(AES.block_size) # we need an IV of 16-bytes, this is also random...
rng = Random.new().read(16)
print "rng = " + str(rng)
encryptor = AES.new(rng, mode, iv)
text = 'j' * 64 + 'i' * 128
ciphertext = encryptor.encrypt(text)
print ciphertext