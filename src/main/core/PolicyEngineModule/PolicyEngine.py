'''
File: PolicyEngine.py
Author: Christopher Wood, caw4567@rit.edu
'''

import sys
sys.path.append("../Common")
import EventInformation

class PolicyEngine(object):
	'''
	The policy engine that will use event, source, and requestor to generate keys (attributes).
	'''

	def handleEventA(self, eventInfo):
		'''
		For event A, we only let the user get access, no exceptions
		'''
		if (eventInfo.targetUser.id == eventInfo.sourceUser.id):
			return eventInfo.sourceUser.attrs 
		else:
			return [] # empty attributes

	def handleEventB(self, eventInfo):
		'''
		For event B, we can let the user and their friends get access, no exceptions
		'''
		if ((eventInfo.targetUser.id == eventInfo.sourceUser.id) or (eventInfo.sourceUser.isFriendsWith(eventInfo.targetUser))):
			return eventInfo.sourceUser.attrs 
		else:
			return [] # empty attributes