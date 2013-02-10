import json

msg = '{"command":"LOGIN","parameters":"caw,pw"}'
data = json.loads(msg)
print(data)
print(data['command'])