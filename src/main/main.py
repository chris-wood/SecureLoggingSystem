'''
File: main.py
Author: Christopher Wood, caw4567@rit.edu
Usage:
	python main.py 
Note: a RabbitMQ server must be running on the localhost to share messages
'''

from __future__ import absolute_import
import pika
from webapp.app import app
from core.ABLSMain import startABLS
import sys

# Create the RabbitMQ broker and then open up a channel to it
connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
channel = connection.channel()
channel.queue_declare(queue='log')
channel.queue_declare(queue='audit')

def main():
	''' Load up the web app and the core ABLS service.
	'''
	print("Starting the ABLS instance")
	startABLS(True) # Start the service in the background (startAll set to true)
	print("Starting the front-end web app")
	app.run(debug=True)

if __name__ == '__main__':
    main()