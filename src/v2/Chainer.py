# 1. define JSON test data
# 2. define stub for function that parses test data and extracts information for the log tables
# 3. write up some basic audit rules

import json

log1 = '{"use": 0, "session": 0}'
log2 = '{"use": 0, "session": 0}'
log3 = '{"use": 0, "session": 0}'
log4 = '{"use": 0, "session": 0}'
log5 = '{"use": 0, "session": 0}'

print (json.loads(log1))


# TODO: write the code to parse everything here
