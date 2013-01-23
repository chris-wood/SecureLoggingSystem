import pickle
key = {"base" : 1, "exponent" : 2}
print key
print pickle.dumps(key)
print pickle.loads(pickle.dumps(key))

