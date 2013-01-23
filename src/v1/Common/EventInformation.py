'''
File: EventInformation.py
Author: Christopher A. Wood, caw4567@rit.edu
'''

class EventInformation(object):
	'''
	Class that wraps up information used in processing of events to determine decryption.
	'''

	def __init__(self, source, target, event):
		'''
		Default constructor, where everything is a string.
		'''
		self.sourceUser = source
		self.targetUser = target
		self.eventId = event